package repositories

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// SessionRepository persists server-side login sessions (P0.3). Sessions are
// keyed by UUID (never sequential ids) so session identifiers leaked into
// logs or JWTs cannot be enumerated.
type SessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, s *models.Session) error {
	if s.TenantID == "" {
		s.TenantID = tenant.FromContext(ctx)
	}
	return r.db.WithContext(ctx).Create(s).Error
}

// FindByID returns the session row, or nil when the id is unknown.
func (r *SessionRepository) FindByID(ctx context.Context, id string) (*models.Session, error) {
	var s models.Session
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&s).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

// FindActiveByUser returns the caller's non-expired, non-revoked sessions,
// newest activity first.
func (r *SessionRepository) FindActiveByUser(ctx context.Context, userID uint) ([]models.Session, error) {
	var rows []models.Session
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked = ? AND expires_at > ?", userID, false, time.Now()).
		Order("last_active_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// FindAllActiveByTenant returns all active sessions for a tenant (P2.3 admin monitor).
func (r *SessionRepository) FindAllActiveByTenant(ctx context.Context, tenantID string) ([]models.Session, error) {
	var rows []models.Session
	if tenantID == "" {
		tenantID = tenant.FromContext(ctx)
	}
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND revoked = ? AND expires_at > ?", tenantID, false, time.Now()).
		Order("last_active_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Touch refreshes a session's device metadata and activity timestamp after a
// rotation. RowsAffected == 0 (unknown/expired session) is NOT an error — the
// caller re-validates the session before rotating.
func (r *SessionRepository) Touch(ctx context.Context, id, ip, ua, deviceName, location string, at time.Time) error {
	return r.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"ip_address":        ip,
			"user_agent":        ua,
			"device_name":       deviceName,
			"location_estimate": location,
			"last_active_at":    at,
		}).Error
}

// RevokeByID marks one session revoked, scoped to userID (IDOR defense).
// Returns gorm.ErrRecordNotFound when no row matched.
func (r *SessionRepository) RevokeByID(ctx context.Context, id string, userID uint) error {
	res := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("revoked", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// RevokeAllForUser revokes every active session of a user.
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error
}

// RevokeAllForUserTx is RevokeAllForUser bound to a caller-provided
// transaction — the credential-change flow revokes sessions inside the SAME
// transaction as the password update.
func (r *SessionRepository) RevokeAllForUserTx(tx *gorm.DB, userID uint) error {
	return tx.Model(&models.Session{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error
}
