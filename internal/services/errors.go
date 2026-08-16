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
	ErrInvalidOTP         = errors.New("invalid or expired code")
	ErrOTPMaxAttempts     = errors.New("too many incorrect attempts, please request a new code")

	// 403
	ErrAccountLocked    = errors.New("account is temporarily locked due to repeated failed attempts")
	ErrAccountDisabled  = errors.New("account is disabled")
	ErrEmailNotVerified = errors.New("email is not verified")

	// 400 — adaptive CAPTCHA (§3): presented when too many failures from an IP
	// make a CAPTCHA mandatory and the request omitted/failed one.
	ErrCaptchaRequired = errors.New("captcha verification required")

	// 404
	ErrUserNotFound    = errors.New("user not found")
	ErrSessionNotFound = errors.New("session not found")

	// 409
	ErrEmailExists    = errors.New("email already registered")
	ErrUsernameExists = errors.New("username already taken")
	// set-password guard: the account already has a usable password and must
	// go through change-password (which verifies the old one) instead.
	ErrPasswordAlreadySet = errors.New("password already set; use change-password instead")

	// 422 / policy
	ErrDisposableEmail = errors.New("disposable email addresses are not allowed")

	// 429 — store-backed velocity limits (§2 registration, §3 per-account login,
	// §5 OTP-per-user). Surfaced as 429 to clients.
	ErrRateLimited = errors.New("rate limit exceeded, please try again later")

	// OTP flow control
	ErrOTPIssue = errors.New("could not issue one-time code")

	// OAuth / Google sign-in
	ErrOAuthStateInvalid            = errors.New("invalid or expired oauth state")
	ErrOAuthEmailNotVerified        = errors.New("google email is not verified")
	ErrOAuthCodeExchangeFailed      = errors.New("failed to exchange authorization code")
	ErrOAuthTokenVerificationFailed = errors.New("failed to verify google id token")
	ErrOAuthNotConfigured           = errors.New("google sign-in is not configured")
)
