package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/finnapigo/finnapigo/internal/audit"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
)

// TrustedDeviceRepo abstracts persistence for trusted devices (P2.4).
type TrustedDeviceRepo interface {
	Create(ctx context.Context, d *models.TrustedDevice) error
	FindByDeviceHash(ctx context.Context, hash string) (*models.TrustedDevice, error)
	TouchUsage(ctx context.Context, id uint, at time.Time) error
	ListByUser(ctx context.Context, userID uint) ([]models.TrustedDevice, error)
	Revoke(ctx context.Context, id, userID uint) error
}

type TrustedDeviceInfo struct {
	ID         uint       `json:"id"`
	DeviceName string     `json:"deviceName"`
	IPAddress  string     `json:"ipAddress"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// TrustedDeviceService manages 30-day "remember me" device tokens (P2.4).
type TrustedDeviceService struct {
	repo   TrustedDeviceRepo
	audits AuditRepo
	ttl    time.Duration
}

func NewTrustedDeviceService(repo TrustedDeviceRepo, audits ...AuditRepo) *TrustedDeviceService {
	var writer AuditRepo
	if len(audits) > 0 {
		writer = audits[0]
	}
	return &TrustedDeviceService{
		repo: repo, audits: writer,
		ttl: 30 * 24 * time.Hour, // 30 days
	}
}

// Issue creates a new trusted device token and persists its SHA-256 hash.
func (s *TrustedDeviceService) issueAudited(ctx context.Context, userID uint, deviceName, ip string) (string, time.Time, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(b)
	hash := hashDeviceToken(token)
	expiresAt := time.Now().Add(s.ttl)

	d := &models.TrustedDevice{
		UserID:     userID,
		DeviceHash: hash,
		DeviceName: deviceName,
		IPAddress:  ip,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		Revoked:    false,
	}

	if s.repo != nil {
		if err := s.repo.Create(ctx, d); err != nil {
			return "", time.Time{}, err
		}
	}
	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{UserID: &userID, Event: "trusted_device_issued", Success: true})
	}
	return token, expiresAt, nil
}

// Validate checks whether a provided device token is valid and unrevoked for the user.
func (s *TrustedDeviceService) validateAudited(ctx context.Context, userID uint, token string) (bool, error) {
	if s.repo == nil || token == "" {
		return false, nil
	}
	hash := hashDeviceToken(token)
	d, err := s.repo.FindByDeviceHash(ctx, hash)
	if err != nil {
		return false, err
	}
	if d == nil || d.UserID != userID || d.Revoked || time.Now().After(d.ExpiresAt) {
		return false, nil
	}

	_ = s.repo.TouchUsage(ctx, d.ID, time.Now())
	if s.audits != nil {
		s.audits.Record(audit.WithActor(ctx, userID), &models.AuditLog{UserID: &userID, Event: models.AuditEventTrustedDeviceUsed, Success: true})
	}
	return true, nil
}

// ListByUser returns active trusted devices for a user.
func (s *TrustedDeviceService) ListByUser(ctx context.Context, userID uint) ([]TrustedDeviceInfo, error) {
	if s.repo == nil {
		return nil, nil
	}
	rows, err := s.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	out := make([]TrustedDeviceInfo, len(rows))
	for i, r := range rows {
		out[i] = TrustedDeviceInfo{
			ID:         r.ID,
			DeviceName: r.DeviceName,
			IPAddress:  r.IPAddress,
			LastUsedAt: r.LastUsedAt,
			ExpiresAt:  r.ExpiresAt,
			CreatedAt:  r.CreatedAt,
		}
	}
	return out, nil
}

// Revoke revokes a trusted device by id for the owning user.
func (s *TrustedDeviceService) revokeAudited(ctx context.Context, id, userID uint) error {
	if s.repo == nil {
		return nil
	}
	if err := s.repo.Revoke(ctx, id, userID); err != nil {
		return err
	}
	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{UserID: &userID, Event: models.AuditEventTrustedDeviceRevoked, Success: true})
	}
	return nil
}

func hashDeviceToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *TrustedDeviceService) Issue(ctx context.Context, userID uint, deviceName, ip string) (string, time.Time, error) {
	var token string
	var expires time.Time
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var err error
		token, expires, err = s.issueAudited(inner, userID, deviceName, ip)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}
func (s *TrustedDeviceService) Validate(ctx context.Context, userID uint, token string) (bool, error) {
	var valid bool
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var err error
		valid, err = s.validateAudited(inner, userID, token)
		return err
	})
	if err != nil {
		return false, err
	}
	return valid, nil
}
func (s *TrustedDeviceService) Revoke(ctx context.Context, id, userID uint) error {
	return runAuditOperation(ctx, s.audits, func(inner context.Context) error { return s.revokeAudited(inner, id, userID) })
}
