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

// RefreshTokenRepo abstracts persistence for refresh tokens. Each token row
// also serves as a session/device record (see §Session & Device Management).
type RefreshTokenRepo interface {
	Create(ctx context.Context, rt *models.RefreshToken) error
	FindByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	// FindActiveByUser returns the caller's non-expired, non-revoked sessions,
	// ordered by most-recently-active first (for the "your devices" list).
	FindActiveByUser(ctx context.Context, userID uint) ([]models.RefreshToken, error)
	// RevokeByID marks the session with the given id as revoked. It must scope
	// the update to the supplied userID so one user cannot revoke another's
	// session (defense against IDOR). Returns ErrSessionNotFound (via gorm's
	// ErrRecordNotFound sentinel → mapped by the service) when no row matches.
	RevokeByID(ctx context.Context, id, userID uint) error
	Revoke(ctx context.Context, rt *models.RefreshToken) error
	RevokeAllForUser(ctx context.Context, userID uint) error
	// TouchLastActive bumps last_active_at for the token — called whenever the
	// session is used (login / refresh rotation). Bounded to the given row id.
	TouchLastActive(ctx context.Context, id uint) error
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

type TOTPRepo interface {
	Upsert(context.Context, *models.TOTPDevice) error
	FindByUserID(context.Context, uint) (*models.TOTPDevice, error)
	// ReplaceRecoveryCodes atomically deletes the user's existing recovery
	// codes (used and unused) and inserts the new batch in one transaction.
	ReplaceRecoveryCodes(context.Context, uint, []*models.RecoveryCode) error
	ActiveRecoveryCodes(context.Context, uint) ([]models.RecoveryCode, error)
	MarkRecoveryCodeUsed(context.Context, *models.RecoveryCode) error
}

// TOTPValidator validates a TOTP code for an already-enabled device. The
// AuthService uses this interface (rather than importing the concrete
// TOTPService) so the validation logic is reused without coupling and the
// service remains trivially unit-testable via a mock.
type TOTPValidator interface {
	Validate(ctx context.Context, userID uint, code string) error
}

// AuditRepo abstracts audit logging.
type AuditRepo interface {
	Record(ctx context.Context, entry *models.AuditLog)
}

// OAuthIdentityRepo abstracts persistence for third-party OAuth identity
// links (e.g. Google, GitHub). Each row maps a (provider, provider_user_id)
// pair to a local user, enabling account linking without duplicating users.
type OAuthIdentityRepo interface {
	Create(ctx context.Context, identity *models.OAuthIdentity) error
	// FindByProviderAndProviderUserID looks up an identity by the provider's
	// stable user ID (e.g. Google's "sub" claim). Returns nil,nil when not
	// found.
	FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*models.OAuthIdentity, error)
	// FindByUserIDAndProvider returns the identity link for a local user + provider.
	FindByUserIDAndProvider(ctx context.Context, userID uint, provider string) (*models.OAuthIdentity, error)
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
