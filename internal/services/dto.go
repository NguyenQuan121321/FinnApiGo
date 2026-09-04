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

// TokenPair is returned by login / refresh-token — the access + refresh pair.
type TokenPair struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"` // access-token expiry
}

// MFAPendingResult is returned by Login when the user has TOTP active. It
// signals the handler to return an mfa_pending token instead of full tokens.
type MFAPendingResult struct {
	MFARequired bool   `json:"mfaRequired"`
	MFAToken    string `json:"mfaToken"`
}

// CompleteMFALoginInput is the input to AuthService.CompleteMFALogin.
type CompleteMFALoginInput struct {
	UserID uint
	Code   string
	IP     string
	UA     string
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

// SessionInfo is the sanitized projection of one active session/device row
// for the "your devices / sessions" list (P0.3 / P1.8). ID is the session UUID.
type SessionInfo struct {
	ID               string    `json:"id"`
	IPAddress        string    `json:"ipAddress"`
	UserAgent        string    `json:"userAgent"`
	DeviceName       string    `json:"deviceName"`
	LocationEstimate string    `json:"locationEstimate"`
	CreatedAt        time.Time `json:"createdAt"`
	LastActiveAt     time.Time `json:"lastActiveAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
	IsCurrent        bool      `json:"isCurrent"`
}

// MFAMethodsResult is the aggregated MFA status for GET /api/v1/auth/mfa/methods (P1.5).
type MFAMethodsResult struct {
	TOTPEnabled            bool   `json:"totpEnabled"`
	PasskeysCount          int    `json:"passkeysCount"`
	RecoveryCodesRemaining int    `json:"recoveryCodesRemaining"`
	DefaultMethod          string `json:"defaultMethod"`
}

// ChangeEmailRequestInput is the input for POST /api/v1/auth/change-email/request (P1.2).
type ChangeEmailRequestInput struct {
	Password string `json:"password" binding:"required"`
	NewEmail string `json:"newEmail" binding:"required,email"`
}

// ChangeEmailConfirmInput is the input for POST /api/v1/auth/change-email/confirm (P1.2).
type ChangeEmailConfirmInput struct {
	Token string `json:"token" binding:"required"`
}

// UserAuditLogItem is the user-facing sanitized audit entry for GET /api/v1/auth/me/audit-log (P1.4).
type UserAuditLogItem struct {
	ID        uint      `json:"id"`
	Event     string    `json:"event"`
	IPAddress string    `json:"ipAddress"`
	Success   bool      `json:"success"`
	CreatedAt time.Time `json:"createdAt"`
}
