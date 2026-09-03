package services

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// AdminRepoInterfaces abstract persistence needs for AdminService.

type AdminUserRepo interface {
	FindByID(ctx context.Context, id uint) (*models.User, error)
	ListPaginated(ctx context.Context, tenantID string, page, limit int, search string) ([]models.User, int64, error)
	SetLock(ctx context.Context, userID uint, lockedUntil *time.Time) error
	BumpPwdVersion(ctx context.Context, userID uint) error
}

type AdminSessionRepo interface {
	FindAllActiveByTenant(ctx context.Context, tenantID string) ([]models.Session, error)
	RevokeAllForUser(ctx context.Context, userID uint) error
}

type AdminAuditRepo interface {
	Record(ctx context.Context, entry *models.AuditLog)
	StreamAll(ctx context.Context, tenantID string) ([]models.AuditLog, error)
}

// AdminService provides tenant administration APIs (P2.3).
type AdminService struct {
	users    AdminUserRepo
	sessions AdminSessionRepo
	tokens   RefreshTokenRepo
	audits   AdminAuditRepo
	store    store.Store
}

func NewAdminService(users AdminUserRepo, sessions AdminSessionRepo, tokens RefreshTokenRepo, audits AdminAuditRepo, store store.Store) *AdminService {
	return &AdminService{
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		audits:   audits,
		store:    store,
	}
}

// ListUsers returns paginated users in the tenant.
func (s *AdminService) ListUsers(ctx context.Context, page, limit int, search string) ([]UserProfile, int64, error) {
	tid := tenant.FromContext(ctx)
	users, total, err := s.users.ListPaginated(ctx, tid, page, limit, search)
	if err != nil {
		return nil, 0, err
	}

	profiles := make([]UserProfile, len(users))
	for i, u := range users {
		profiles[i] = UserProfile{
			ID:              u.ID,
			Username:        u.Username,
			Email:           u.Email,
			FullName:        u.FullName,
			Role:            u.Role,
			IsActive:        u.IsActive,
			IsEmailVerified: u.IsEmailVerified,
		}
	}
	return profiles, total, nil
}

// LockUser locks a user account for lockDuration.
func (s *AdminService) LockUser(ctx context.Context, adminID, targetUserID uint, lockDuration time.Duration, ip string) error {
	if adminID == targetUserID {
		return ErrCannotLockSelf
	}

	u, err := s.users.FindByID(ctx, targetUserID)
	if err != nil {
		return err
	}
	if u == nil {
		return ErrUserNotFound
	}

	if lockDuration <= 0 {
		lockDuration = 24 * time.Hour * 365 * 10 // 10 years (indefinite)
	}
	lockedUntil := time.Now().Add(lockDuration)
	if err := s.users.SetLock(ctx, targetUserID, &lockedUntil); err != nil {
		return err
	}

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			TenantID:  tenant.FromContext(ctx),
			UserID:    &adminID,
			Email:     u.Email,
			Event:     models.AuditEventAdminAction,
			IPAddress: ip,
			Success:   true,
			Detail:    fmt.Sprintf("locked user %d until %s", targetUserID, lockedUntil.Format(time.RFC3339)),
		})
	}
	return nil
}

// UnlockUser unlocks a user account and resets failed login counters.
func (s *AdminService) UnlockUser(ctx context.Context, adminID, targetUserID uint, ip string) error {
	u, err := s.users.FindByID(ctx, targetUserID)
	if err != nil {
		return err
	}
	if u == nil {
		return ErrUserNotFound
	}

	if err := s.users.SetLock(ctx, targetUserID, nil); err != nil {
		return err
	}

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			TenantID:  tenant.FromContext(ctx),
			UserID:    &adminID,
			Email:     u.Email,
			Event:     models.AuditEventAdminAction,
			IPAddress: ip,
			Success:   true,
			Detail:    fmt.Sprintf("unlocked user %d", targetUserID),
		})
	}
	return nil
}

// ForceLogout immediately revokes all refresh tokens, sessions, and bumps pwd_version.
func (s *AdminService) ForceLogout(ctx context.Context, adminID, targetUserID uint, ip string) error {
	u, err := s.users.FindByID(ctx, targetUserID)
	if err != nil {
		return err
	}
	if u == nil {
		return ErrUserNotFound
	}

	if s.tokens != nil {
		_ = s.tokens.RevokeAllForUser(ctx, targetUserID)
	}
	if s.sessions != nil {
		_ = s.sessions.RevokeAllForUser(ctx, targetUserID)
	}
	_ = s.users.BumpPwdVersion(ctx, targetUserID)
	if s.store != nil {
		s.store.Delete(fmt.Sprintf("pwdver:%d", targetUserID))
	}

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			TenantID:  tenant.FromContext(ctx),
			UserID:    &adminID,
			Email:     u.Email,
			Event:     models.AuditEventAdminAction,
			IPAddress: ip,
			Success:   true,
			Detail:    fmt.Sprintf("forced logout for user %d (sessions and tokens revoked)", targetUserID),
		})
	}
	return nil
}

// ListTenantSessions lists all active sessions in the tenant.
func (s *AdminService) ListTenantSessions(ctx context.Context) ([]SessionInfo, error) {
	if s.sessions == nil {
		return nil, nil
	}
	tid := tenant.FromContext(ctx)
	rows, err := s.sessions.FindAllActiveByTenant(ctx, tid)
	if err != nil {
		return nil, err
	}

	out := make([]SessionInfo, len(rows))
	for i, r := range rows {
		out[i] = SessionInfo{
			ID:               r.ID,
			IPAddress:        r.IPAddress,
			UserAgent:        r.UserAgent,
			DeviceName:       r.DeviceName,
			LocationEstimate: r.LocationEstimate,
			LastActiveAt:     r.LastActiveAt,
			ExpiresAt:        r.ExpiresAt,
			CreatedAt:        r.CreatedAt,
			IsCurrent:        false,
		}
	}
	return out, nil
}

// ExportAuditLogs streams all audit entries for the tenant in CSV or NDJSON format.
func (s *AdminService) ExportAuditLogs(ctx context.Context, format string) ([]byte, string, error) {
	if s.audits == nil {
		return nil, "", nil
	}
	tid := tenant.FromContext(ctx)
	entries, err := s.audits.StreamAll(ctx, tid)
	if err != nil {
		return nil, "", err
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "ndjson" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, e := range entries {
			if err := enc.Encode(e); err != nil {
				return nil, "", err
			}
		}
		return buf.Bytes(), "application/x-ndjson", nil
	}

	// Default to CSV
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"id", "tenant_id", "user_id", "email", "event", "ip_address", "success", "detail", "prev_hash", "record_hash", "created_at"})
	for _, e := range entries {
		var uidStr string
		if e.UserID != nil {
			uidStr = strconv.FormatUint(uint64(*e.UserID), 10)
		}
		_ = w.Write([]string{
			strconv.FormatUint(uint64(e.ID), 10),
			e.TenantID,
			uidStr,
			e.Email,
			e.Event,
			e.IPAddress,
			strconv.FormatBool(e.Success),
			e.Detail,
			e.PrevHash,
			e.RecordHash,
			e.CreatedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
	return buf.Bytes(), "text/csv", nil
}
