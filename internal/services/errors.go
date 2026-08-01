package services

import "errors"

// Service-level sentinel errors. Handlers translate these into HTTP status
// codes and the standardized response envelope — services never touch HTTP.

var (
	// 400 / validation-ish
	ErrInvalidInput          = errors.New("invalid input")
	ErrPasswordTooWeak       = errors.New("password does not meet complexity requirements")

	// 401
	ErrInvalidCredentials    = errors.New("invalid email or password")
	ErrInvalidToken          = errors.New("invalid or expired token")
	ErrInvalidOTP            = errors.New("invalid or expired code")
	ErrOTPMaxAttempts        = errors.New("too many incorrect attempts, please request a new code")

	// 403
	ErrAccountLocked         = errors.New("account is temporarily locked due to repeated failed attempts")
	ErrAccountDisabled       = errors.New("account is disabled")
	ErrEmailNotVerified      = errors.New("email is not verified")

	// 404
	ErrUserNotFound          = errors.New("user not found")

	// 409
	ErrEmailExists           = errors.New("email already registered")
	ErrUsernameExists        = errors.New("username already taken")

	// OTP flow control
	ErrOTPIssue              = errors.New("could not issue one-time code")
)
