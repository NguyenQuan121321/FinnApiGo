// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
)

// ---- Repository interfaces (consumer-driven, mockable) ----

// UserRepo abstracts persistence for users.
type UserRepo interface {
	Create(user *models.User) error
	FindByID(id uint) (*models.User, error)
	FindByEmail(email string) (*models.User, error)
	FindByUsername(username string) (*models.User, error)
	Update(user *models.User) error
	UpdatePassword(user *models.User, hashedPassword string) error
	IncrementFailedAttempts(user *models.User, lockUntil *time.Time) error
	ResetFailedAttempts(user *models.User) error
	SetEmailVerified(user *models.User, verified bool) error
}

// RefreshTokenRepo abstracts persistence for refresh tokens.
type RefreshTokenRepo interface {
	Create(rt *models.RefreshToken) error
	FindByHash(hash string) (*models.RefreshToken, error)
	Revoke(rt *models.RefreshToken) error
	RevokeAllForUser(userID uint) error
	PurgeExpired(before time.Time) (int64, error)
}

// OtpRepo abstracts persistence for OTP codes.
type OtpRepo interface {
	Create(o *models.OtpCode) error
	FindLatestActive(userID uint, purpose string) (*models.OtpCode, error)
	Update(o *models.OtpCode) error
	MarkUsed(o *models.OtpCode) error
	IncrementAttempts(o *models.OtpCode) (int, error)
	PurgeExpired(before time.Time) (int64, error)
}

// AuditRepo abstracts audit logging.
type AuditRepo interface {
	Record(entry *models.AuditLog)
}

// ---- Notifier (for OTP / reset emails) ----

// Notifier delivers OTP / password-reset messages. The default implementation
// logs to console; swap for an SMTP-backed one in production.
type Notifier interface {
	SendOTP(to, code, purpose string) error
	SendPasswordReset(to, resetToken string) error
}
