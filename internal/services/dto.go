package services

import (
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
)

// ---- Data Transfer Objects ----
// These structs are the service-layer inputs/outputs. Handlers map HTTP
// request bodies into these and map outputs into HTTP responses. Keeping
// them in the service package means the business logic has a stable contract
// independent of transport details.

// RegisterInput is the input to AuthService.Register.
type RegisterInput struct {
	Username string
	Email    string
	Password string
	FullName string
	IP       string // §2 — registration velocity limit is keyed per IP
}

// LoginInput is the input to AuthService.Login.
type LoginInput struct {
	Email        string
	Password     string
	CaptchaToken string // §3 — required only after repeated failures from an IP
}

// ChangePasswordInput is the input to AuthService.ChangePassword.
type ChangePasswordInput struct {
	UserID      uint
	OldPassword string
	NewPassword string
}

// ResetPasswordInput is the input to AuthService.ResetPassword.
type ResetPasswordInput struct {
	Token       string
	NewPassword string
}

// EmailVerifyInput is the input to AuthService.VerifyEmail.
type EmailVerifyInput struct {
	Token string
}

// OTPSendInput is the input to MFAService.SendOTP.
type OTPSendInput struct {
	UserID uint
	Purpose string
}

// OTPVerifyInput is the input to MFAService.VerifyOTP.
type OTPVerifyInput struct {
	UserID uint
	Code   string
	Purpose string
}

// TokenPair is returned by login / refresh-token — the access + refresh pair.
type TokenPair struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"` // access-token expiry
}

// UserProfile is the sanitized user payload for /me and /login responses.
type UserProfile struct {
	ID              uint      `json:"id"`
	Username        string    `json:"username"`
	Email           string    `json:"email"`
	FullName        string    `json:"fullName"`
	Role            string    `json:"role"`
	IsActive        bool      `json:"isActive"`
	IsEmailVerified bool      `json:"isEmailVerified"`
	CreatedAt       time.Time `json:"createdAt"`
}

// FromUser builds a UserProfile from a model, stripping the password hash.
func FromUser(u *models.User) UserProfile {
	return UserProfile{
		ID: u.ID, Username: u.Username, Email: u.Email, FullName: u.FullName,
		Role: u.Role, IsActive: u.IsActive, IsEmailVerified: u.IsEmailVerified,
		CreatedAt: u.CreatedAt,
	}
}

// SessionInfo is the sanitized projection of one active refresh-token row for
// the "your devices / sessions" list. It deliberately omits the token hash.
type SessionInfo struct {
	ID              uint      `json:"id"`
	IPAddress       string    `json:"ipAddress"`
	UserAgent       string    `json:"userAgent"`
	DeviceName      string    `json:"deviceName"`
	LocationEstimate string   `json:"locationEstimate"`
	CreatedAt       time.Time `json:"createdAt"`
	LastActiveAt    time.Time `json:"lastActiveAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
