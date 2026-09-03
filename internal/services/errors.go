package services

import "errors"

// Service-level sentinel errors. Handlers translate these into HTTP status
// codes and the standardized response envelope — services never touch HTTP.

var (
	// 400 / validation-ish
	ErrInvalidInput    = errors.New("invalid input")
	ErrPasswordTooWeak = errors.New("password does not meet complexity requirements")

	// 401
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrInvalidCode        = errors.New("invalid or expired code")

	// 403
	ErrAccountLocked    = errors.New("account is temporarily locked due to repeated failed attempts")
	ErrAccountDisabled  = errors.New("account is disabled")
	ErrEmailNotVerified = errors.New("email is not verified")
	// rotating an ACTIVE TOTP device requires a sudo token (minted only after
	// a current TOTP proof) — a bare access token must not touch MFA.
	ErrSudoRequired = errors.New("sudo verification required")

	// 400 — adaptive CAPTCHA (§3): presented when too many failures from an IP
	// make a CAPTCHA mandatory and the request omitted/failed one.
	ErrCaptchaRequired = errors.New("captcha verification required")

	// 404
	ErrUserNotFound = errors.New("user not found")
	// ErrTOTPUnrecoverable means the device's sealed TOTP secret cannot be
	// opened with the active key and no legacy fallback exists — the user
	// must re-enroll MFA (mapped to a 4xx, never an opaque 500).
	ErrTOTPUnrecoverable = errors.New("totp configuration is invalid; please re-enroll MFA")
	ErrSessionNotFound   = errors.New("session not found")

	// 409
	ErrEmailExists    = errors.New("email already registered")
	ErrUsernameExists = errors.New("username already taken")
	// set-password guard: the account already has a usable password and must
	// go through change-password (which verifies the old one) instead.
	ErrPasswordAlreadySet = errors.New("password already set; use change-password instead")

	// 422 / policy
	ErrDisposableEmail = errors.New("disposable email addresses are not allowed")
	// ErrPasswordBreached — the chosen password appears in known breach
	// corpora (NIST 800-63B compromised-credential screening). The check is
	// best-effort and fails OPEN, so this error only fires on a confirmed hit.
	ErrPasswordBreached = errors.New("password appears in known data breaches — choose a different one")

	// 429 — store-backed velocity limits (§2 registration, §3 per-account
	// login). Surfaced as 429 to clients.
	ErrRateLimited = errors.New("rate limit exceeded, please try again later")

	// OAuth / Google sign-in
	ErrOAuthStateInvalid            = errors.New("invalid or expired oauth state")
	ErrOAuthEmailNotVerified        = errors.New("google email is not verified")
	ErrOAuthCodeExchangeFailed      = errors.New("failed to exchange authorization code")
	ErrOAuthTokenVerificationFailed = errors.New("failed to verify google id token")
	ErrOAuthNotConfigured           = errors.New("google sign-in is not configured")
	// ErrOAuthEmailTaken — a Google identity presented an email that belongs
	// to an existing LOCAL account whose email was never verified. The link
	// is refused (auto-linking an unverified local account is the classic
	// account-takeover pattern); the legitimate owner must verify the email
	// first or sign in with their password.
	ErrOAuthEmailTaken = errors.New("an account with this email already exists — verify the email or sign in with your password")
	// ErrCannotUnlinkOnlyMethod (P1.6) prevents removing the sole authentication method.
	ErrCannotUnlinkOnlyMethod = errors.New("cannot unlink the only authentication method without setting a password")
	// ErrCannotLockSelf (P2.3) prevents admin self-lockout.
	ErrCannotLockSelf = errors.New("cannot lock own account")
)
