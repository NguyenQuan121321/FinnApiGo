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

	// 429 — store-backed velocity limits (§2 registration, §3 per-account
	// login). Surfaced as 429 to clients.
	ErrRateLimited = errors.New("rate limit exceeded, please try again later")

	// OAuth / Google sign-in
	ErrOAuthStateInvalid            = errors.New("invalid or expired oauth state")
	ErrOAuthEmailNotVerified        = errors.New("google email is not verified")
	ErrOAuthCodeExchangeFailed      = errors.New("failed to exchange authorization code")
	ErrOAuthTokenVerificationFailed = errors.New("failed to verify google id token")
	ErrOAuthNotConfigured           = errors.New("google sign-in is not configured")
)
