// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"context"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
)

// ---- Repository interfaces (consumer-driven, mockable) ----
// Every method takes context.Context as its first parameter (§1.4) so that
// request deadlines and client disconnects propagate into DB queries.

// UserRepo abstracts persistence for users.
type UserRepo interface {
	Create(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id uint) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByUsername(ctx context.Context, username string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	UpdatePassword(ctx context.Context, user *models.User, hashedPassword string) error
	IncrementFailedAttempts(ctx context.Context, user *models.User, lockUntil *time.Time) error
	ResetFailedAttempts(ctx context.Context, user *models.User) error
	SetEmailVerified(ctx context.Context, user *models.User, verified bool) error
}

// RefreshTokenRepo abstracts persistence for refresh tokens.
type RefreshTokenRepo interface {
	Create(ctx context.Context, rt *models.RefreshToken) error
	FindByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	Revoke(ctx context.Context, rt *models.RefreshToken) error
	RevokeAllForUser(ctx context.Context, userID uint) error
	PurgeExpired(ctx context.Context, before time.Time) (int64, error)
}

// OtpRepo abstracts persistence for OTP codes.
type OtpRepo interface {
	Create(ctx context.Context, o *models.OtpCode) error
	FindLatestActive(ctx context.Context, userID uint, purpose string) (*models.OtpCode, error)
	Update(ctx context.Context, o *models.OtpCode) error
	MarkUsed(ctx context.Context, o *models.OtpCode) error
	IncrementAttempts(ctx context.Context, o *models.OtpCode) (int, error)
	PurgeExpired(ctx context.Context, before time.Time) (int64, error)
}

// AuditRepo abstracts audit logging.
type AuditRepo interface {
	Record(ctx context.Context, entry *models.AuditLog)
}

// UsedTokenRepo abstracts single-use token (jti) tracking (§1.8).
type UsedTokenRepo interface {
	MarkUsed(ctx context.Context, jti, tokenType string, userID uint, exp time.Time) (bool, error)
	IsUsed(ctx context.Context, jti string) (bool, error)
}

// ---- Notifier (for OTP / reset / verify emails) ----

// Notifier delivers OTP / password-reset / email-verification messages.
// The default implementation logs to console; swap for an SMTP-backed one
// in production.
type Notifier interface {
	SendOTP(to, code, purpose string) error
	SendPasswordReset(to, resetToken string) error
	SendEmailVerification(to, verifyToken string) error
}

// ---- CAPTCHA verifier (§2) ----

// CaptchaVerifier validates a client-provided CAPTCHA token against the
// upstream provider. NoOpVerifier (always nil) is used when CAPTCHA is
// disabled (the default).
type CaptchaVerifier interface {
	Verify(ctx context.Context, token string) error
}
