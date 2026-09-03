// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"context"
	"time"

	"gorm.io/gorm"

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
	// BumpPwdVersion atomically increments users.pwd_version — called on
	// every credential change so outstanding access tokens die (A7).
	BumpPwdVersion(ctx context.Context, userID uint) error
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
	// Revoke marks the given token row revoked via compare-and-set
	// (WHERE revoked = false). It returns repositories.ErrTokenAlreadyRevoked
	// when the row was already revoked by a concurrent request — callers must
	// treat that as token reuse, not as an error to propagate.
	Revoke(ctx context.Context, rt *models.RefreshToken) error
	RevokeAllForUser(ctx context.Context, userID uint) error
	// RevokeBySession revokes every refresh token linked to one session family
	// (P0.3) — the scoped alternative to RevokeAllForUser when only one
	// device's chain must die.
	RevokeBySession(ctx context.Context, sessionID string) error
	PurgeExpired(ctx context.Context, before time.Time) (int64, error)
}

// SessionRepo abstracts persistence for server-side login sessions (P0.3).
// One row per successful authentication; refresh tokens and access tokens
// (sid claim) belong to exactly one session, giving token-family isolation.
type SessionRepo interface {
	Create(ctx context.Context, s *models.Session) error
	// FindByID returns the session row or nil when unknown/soft-deleted.
	FindByID(ctx context.Context, id string) (*models.Session, error)
	// FindActiveByUser returns the caller's non-expired, non-revoked sessions,
	// most-recently-active first (drives GET /auth/sessions).
	FindActiveByUser(ctx context.Context, userID uint) ([]models.Session, error)
	// Touch updates a session's device metadata and activity timestamp after
	// a rotation (the family stays the same; the view stays current).
	Touch(ctx context.Context, id, ip, ua, device, location string, at time.Time) error
	// RevokeByID marks one session revoked, scoped to userID (IDOR defense).
	// Returns gorm.ErrRecordNotFound when no row matched.
	RevokeByID(ctx context.Context, id string, userID uint) error
	// RevokeAllForUser revokes every active session of a user.
	RevokeAllForUser(ctx context.Context, userID uint) error
	// RevokeAllForUserTx is RevokeAllForUser bound to a caller-provided
	// transaction (credential-change atomicity).
	RevokeAllForUserTx(tx *gorm.DB, userID uint) error
}

type TOTPRepo interface {
	Upsert(context.Context, *models.TOTPDevice) error
	FindByUserID(context.Context, uint) (*models.TOTPDevice, error)
	// ReplaceRecoveryCodes atomically deletes the user's existing recovery
	// codes (used and unused) and inserts the new batch in one transaction.
	ReplaceRecoveryCodes(context.Context, uint, []*models.RecoveryCode) error
	ActiveRecoveryCodes(context.Context, uint) ([]models.RecoveryCode, error)
	// MarkRecoveryCodeUsed marks the code consumed via compare-and-set on
	// used_at IS NULL; it returns repositories.ErrRecoveryCodeUsed when a
	// concurrent request already consumed the code — callers must treat that
	// as a failed attempt, not propagate it.
	MarkRecoveryCodeUsed(context.Context, *models.RecoveryCode) error
	// Disable deactivates the user's TOTP device and clears stored secrets (P1.1).
	Disable(context.Context, uint) error
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
	FindByUserIDPaginated(ctx context.Context, userID uint, page, limit int) ([]models.AuditLog, int64, error)
	AnonymizeUser(ctx context.Context, userID uint) error
	StreamAll(ctx context.Context, tenantID string) ([]models.AuditLog, error)
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
	// DeleteByUserIDAndProvider unlinks an OAuth identity (P1.6).
	DeleteByUserIDAndProvider(ctx context.Context, userID uint, provider string) error
	// DeleteAllByUserID removes all OAuth identities for a user upon erasure (P1.3).
	DeleteAllByUserID(ctx context.Context, userID uint) error
}

// UsedTokenRepo abstracts single-use token (jti) tracking (§1.8).
type UsedTokenRepo interface {
	MarkUsed(ctx context.Context, jti, tokenType string, userID uint, exp time.Time) (bool, error)
	IsUsed(ctx context.Context, jti string) (bool, error)
}

// ---- Notifier (for reset / verify / alert emails) ----

// Notifier delivers password-reset / email-verification messages and
// security-transparency alerts. The default implementation logs to console;
// swap for an SMTP-backed one in production. Implementations must honor the
// context (A2) so request cancellation and deadlines propagate into delivery.
type Notifier interface {
	SendPasswordReset(ctx context.Context, to, resetToken string) error
	SendEmailVerification(ctx context.Context, to, verifyToken string) error
	// SendNewLoginAlert notifies the user of a sign-in from an IP not seen in
	// the lookback window. TRANSPARENCY ONLY — deliberately not risk-based
	// authentication: no step-up, no blocking (product decision for
	// predictable UX across deployments). The message carries no secrets.
	SendNewLoginAlert(ctx context.Context, to, ip, device string) error
	// SendDuplicateRegisterAlert warns the OWNER of an existing account that
	// someone attempted to register with their email/username (P0.1). The
	// registration response itself is a neutral 201, so this email is the
	// user-visible signal. No tokens, no links.
	SendDuplicateRegisterAlert(ctx context.Context, to string) error
	// SendSecurityAlert delivers a generic security-transparency notice
	// (token reuse detected, account deactivated, MFA disabled, email
	// change, ...). detail is a short human label already sanitized by the
	// caller. The message carries no tokens or links.
	SendSecurityAlert(ctx context.Context, to, event, detail string) error
}

// ---- CAPTCHA verifier (§2) ----

// CaptchaVerifier validates a client-provided CAPTCHA token against the
// upstream provider. NoOpVerifier (always nil) is used when CAPTCHA is
// disabled (the default).
type CaptchaVerifier interface {
	Verify(ctx context.Context, token string) error
}
