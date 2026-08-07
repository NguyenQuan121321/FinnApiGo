package handlers

import "github.com/finnapigo/finnapigo/internal/services"

// HTTP request/response payload structs. Each endpoint that accepts a body has
// a dedicated struct with gin binding tags — never accept raw maps.
//
// §5 — Every text field has an explicit max length (defends against unbounded
// payloads even before the global body-size limit kicks in).

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,min=8,max=128"`
	FullName string `json:"fullName" binding:"required,max=255"`
	// §2 — CaptchaToken is verified server-side when CAPTCHA is configured.
	// Optional so the endpoint still works with CAPTCHA disabled (default).
	CaptchaToken string `json:"captchaToken"`
	// §2 — Honeypot: hidden field real users never fill. Non-empty => bot.
	Website string `json:"website"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,max=128"`
	// §3 — optional captcha; required only after repeated failures from an IP.
	CaptchaToken string `json:"captchaToken"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email,max=255"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required,min=8,max=128"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required,max=128"`
	NewPassword string `json:"newPassword" binding:"required,min=8,max=128"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type ResendVerifyEmailRequest struct {
	Email string `json:"email" binding:"required,email,max=255"`
}

type OTPSendRequest struct {
	Purpose string `json:"purpose" binding:"required"`
}

type OTPVerifyRequest struct {
	Code    string `json:"code" binding:"required,len=6"`
	Purpose string `json:"purpose" binding:"required"`
}
type TOTPCodeRequest struct {
	Code string `json:"code" binding:"required,min=6,max=128"`
}

// ---- response payloads ----

// §1.1 — RegisterResponse no longer carries the verification token.
type RegisterResponse struct {
	Profile services.UserProfile `json:"profile"`
}

type LoginResponse struct {
	Profile services.UserProfile `json:"profile"`
	services.TokenPair
}

type MessageOnly struct {
	Message string `json:"message,omitempty"`
}
