// Package swagger provides typed response structs used exclusively by swag
// annotations. The handler layer returns response.APIResponse (with interface{}
// data), which is ergonomic at runtime but opaque to the swag code generator.
// These structs give swag concrete types so the generated OpenAPI spec contains
// accurate, fully-documented response schemas.
//
// This package is NEVER imported at runtime — only referenced in swag comments.
package swagger

import (
	"encoding/json"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
)

// --------------------------------------------------------------------------
// Base envelope
// --------------------------------------------------------------------------

// Envelope is the standard API response wrapper. Every endpoint returns this
// shape; the Data field varies per endpoint.
type Envelope struct {
	Code    int    `json:"code" example:"200"`
	Message string `json:"message" example:"ok"`
}

// NullDataEnvelope is returned when the operation has no meaningful payload.
type NullDataEnvelope struct {
	Code    int    `json:"code" example:"200"`
	Message string `json:"message" example:"operation successful"`
	Data    *any   `json:"data" swaggertype:"string" example:"null"`
}

// ErrorEnvelope is the standard error response.
type ErrorEnvelope struct {
	Code    int    `json:"code" example:"400"`
	Message string `json:"message" example:"validation error"`
	Data    *any   `json:"data" swaggertype:"string" example:"null"`
}

// --------------------------------------------------------------------------
// Health
// --------------------------------------------------------------------------

// HealthData is the payload of /healthz and /readyz.
type HealthData struct {
	Status string `json:"status" example:"ok"`
	DB     string `json:"db,omitempty" example:"up"`
}

// HealthEnvelope wraps a health-check response.
type HealthEnvelope struct {
	Code    int        `json:"code" example:"200"`
	Message string     `json:"message" example:"ok"`
	Data    HealthData `json:"data"`
}

// --------------------------------------------------------------------------
// User profile (shared across register, login, /me)
// --------------------------------------------------------------------------

// UserProfile is the sanitized user payload.
type UserProfile struct {
	ID              uint      `json:"id" example:"42"`
	Username        string    `json:"username" example:"johndoe"`
	Email           string    `json:"email" example:"john@example.com"`
	FullName        string    `json:"fullName" example:"John Doe"`
	Role            string    `json:"role" example:"user"`
	IsActive        bool      `json:"isActive" example:"true"`
	IsEmailVerified bool      `json:"isEmailVerified" example:"false"`
	CreatedAt       time.Time `json:"createdAt" example:"2026-01-15T10:30:00Z"`
}

// --------------------------------------------------------------------------
// Token pair
// --------------------------------------------------------------------------

// TokenPair is the access + refresh token pair.
type TokenPair struct {
	AccessToken  string    `json:"accessToken" example:"eyJhbGciOiJIUzI1NiIs..."`
	RefreshToken string    `json:"refreshToken" example:"dGhpcyBpcyBhIHJlZnJl..."`
	ExpiresAt    time.Time `json:"expiresAt" example:"2026-01-15T11:30:00Z"`
}

// --------------------------------------------------------------------------
// Auth responses
// --------------------------------------------------------------------------

// RegisterData is the payload of POST /api/v1/auth/register.
type RegisterData struct {
	Profile UserProfile `json:"profile"`
}

// RegisterEnvelope wraps a registration success response.
type RegisterEnvelope struct {
	Code    int          `json:"code" example:"201"`
	Message string       `json:"message" example:"account created"`
	Data    RegisterData `json:"data"`
}

// LoginData is the payload of POST /api/v1/auth/login on success. It mirrors
// handlers.LoginResponse exactly: the profile is nested under "profile" while
// the token pair is inlined alongside it.
type LoginData struct {
	Profile UserProfile `json:"profile"`
	TokenPair
}

// LoginEnvelope wraps a login success response.
type LoginEnvelope struct {
	Code    int       `json:"code" example:"200"`
	Message string    `json:"message" example:"login successful"`
	Data    LoginData `json:"data"`
}

// MFAPendingData is returned when TOTP verification is required.
type MFAPendingData struct {
	MFARequired bool   `json:"mfaRequired" example:"true"`
	MFAToken    string `json:"mfaToken" example:"eyJhbGciOiJIUzI1NiIs..."`
}

// MFAPendingEnvelope wraps an MFA-pending response.
type MFAPendingEnvelope struct {
	Code    int            `json:"code" example:"200"`
	Message string         `json:"message" example:"mfa required"`
	Data    MFAPendingData `json:"data"`
}

// TokenPairEnvelope wraps a token-pair response (refresh).
type TokenPairEnvelope struct {
	Code    int       `json:"code" example:"200"`
	Message string    `json:"message" example:"token refreshed"`
	Data    TokenPair `json:"data"`
}

// UserProfileEnvelope wraps a user profile response (/me).
type UserProfileEnvelope struct {
	Code    int         `json:"code" example:"200"`
	Message string      `json:"message" example:"profile fetched"`
	Data    UserProfile `json:"data"`
}

// --------------------------------------------------------------------------
// Sessions
// --------------------------------------------------------------------------

// SessionInfo is one active session/device row.
type SessionInfo struct {
	ID               string    `json:"id" example:"9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"`
	IPAddress        string    `json:"ipAddress" example:"192.168.1.100"`
	UserAgent        string    `json:"userAgent" example:"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`
	DeviceName       string    `json:"deviceName" example:"Chrome on Windows"`
	LocationEstimate string    `json:"locationEstimate" example:"Ho Chi Minh City, VN"`
	CreatedAt        time.Time `json:"createdAt" example:"2026-01-15T10:30:00Z"`
	LastActiveAt     time.Time `json:"lastActiveAt" example:"2026-01-15T11:00:00Z"`
	ExpiresAt        time.Time `json:"expiresAt" example:"2026-01-22T10:30:00Z"`
	IsCurrent        bool      `json:"isCurrent" example:"true"`
}

// SessionsData is the payload of GET /api/v1/auth/sessions.
type SessionsData struct {
	Sessions []SessionInfo `json:"sessions"`
}

// SessionsEnvelope wraps a session-list response.
type SessionsEnvelope struct {
	Code    int          `json:"code" example:"200"`
	Message string       `json:"message" example:"sessions fetched"`
	Data    SessionsData `json:"data"`
}

// --------------------------------------------------------------------------
// TOTP / MFA
// --------------------------------------------------------------------------

// TOTPEnableData is the payload of POST /api/v1/auth/mfa/totp/enable.
type TOTPEnableData struct {
	Secret          string `json:"secret" example:"JBSWY3DPEHPK3PXP"`
	ProvisioningURI string `json:"provisioningURI" example:"otpauth://totp/FinnApiGo:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=FinnApiGo"`
}

// TOTPEnableEnvelope wraps a TOTP enrollment response.
type TOTPEnableEnvelope struct {
	Code    int            `json:"code" example:"200"`
	Message string         `json:"message" example:"TOTP enrollment pending verification"`
	Data    TOTPEnableData `json:"data"`
}

// RecoveryCodesData is the payload when recovery codes are returned.
type RecoveryCodesData struct {
	RecoveryCodes []string `json:"recoveryCodes" example:"a1b2c3d4e5f6,g7h8i9j0k1l2"`
}

// RecoveryCodesEnvelope wraps a recovery-codes response (verify/regenerate).
type RecoveryCodesEnvelope struct {
	Code    int               `json:"code" example:"200"`
	Message string            `json:"message" example:"TOTP enabled"`
	Data    RecoveryCodesData `json:"data"`
}

// RecoveryCodesViewData is the payload of POST /api/v1/auth/mfa/totp/recovery-codes.
type RecoveryCodesViewData struct {
	RecoveryCodes    []string `json:"recoveryCodes" example:"a1b2c3d4e5f6,g7h8i9j0k1l2"`
	SudoToken        string   `json:"sudoToken" example:"eyJhbGciOiJIUzI1NiIs..."`
	SudoExpiresInSec int      `json:"sudoExpiresInSec" example:"900"`
}

// RecoveryCodesViewEnvelope wraps a recovery-codes-view response with sudo token.
type RecoveryCodesViewEnvelope struct {
	Code    int                   `json:"code" example:"200"`
	Message string                `json:"message" example:"Recovery codes"`
	Data    RecoveryCodesViewData `json:"data"`
}

// --------------------------------------------------------------------------
// Passkeys / WebAuthn
// --------------------------------------------------------------------------

// PasskeyOptionsEnvelope wraps WebAuthn creation/assertion options.
// The data payload is opaque (pass verbatim to the browser WebAuthn API).
type PasskeyOptionsEnvelope struct {
	Code    int             `json:"code" example:"200"`
	Message string          `json:"message" example:"passkey registration challenge"`
	Data    json.RawMessage `json:"data" swaggertype:"object"`
}

// PasskeyRegisteredData is the payload of POST /api/v1/auth/mfa/passkey/register/verify.
type PasskeyRegisteredData struct {
	ID          uint      `json:"id" example:"1"`
	DisplayName string    `json:"displayName" example:"My YubiKey"`
	Transports  string    `json:"transports" example:"[\"usb\"]"`
	CreatedAt   time.Time `json:"createdAt" example:"2026-01-15T10:30:00Z"`
}

// PasskeyRegisteredEnvelope wraps a passkey-registered response.
type PasskeyRegisteredEnvelope struct {
	Code    int                   `json:"code" example:"201"`
	Message string                `json:"message" example:"passkey registered"`
	Data    PasskeyRegisteredData `json:"data"`
}

// PasskeysListData is the payload of GET /api/v1/auth/mfa/passkeys.
type PasskeysListData struct {
	Passkeys []models.PasskeyCredential `json:"passkeys"`
}

// PasskeysListEnvelope wraps a passkeys-list response.
type PasskeysListEnvelope struct {
	Code    int              `json:"code" example:"200"`
	Message string           `json:"message" example:"passkeys fetched"`
	Data    PasskeysListData `json:"data"`
}

// UserAuditLogData is the payload of GET /api/v1/auth/me/audit-log.
type UserAuditLogData struct {
	Items []models.AuditLog `json:"items"`
	Total int64             `json:"total" example:"15"`
	Page  int               `json:"page" example:"1"`
	Limit int               `json:"limit" example:"20"`
}

// UserAuditLogEnvelope wraps GET /api/v1/auth/me/audit-log response.
type UserAuditLogEnvelope struct {
	Code    int              `json:"code" example:"200"`
	Message string           `json:"message" example:"audit log"`
	Data    UserAuditLogData `json:"data"`
}

// MFAMethodsData is the payload of GET /api/v1/auth/mfa/methods.
type MFAMethodsData struct {
	TOTPEnabled            bool   `json:"totpEnabled" example:"true"`
	PasskeysCount          int    `json:"passkeysCount" example:"1"`
	RecoveryCodesRemaining int    `json:"recoveryCodesRemaining" example:"8"`
	DefaultMethod          string `json:"defaultMethod" example:"totp"`
}

// MFAMethodsEnvelope wraps GET /api/v1/auth/mfa/methods response.
type MFAMethodsEnvelope struct {
	Code    int            `json:"code" example:"200"`
	Message string         `json:"message" example:"mfa methods"`
	Data    MFAMethodsData `json:"data"`
}

// --------------------------------------------------------------------------
// Phase 2 Enterprise: Admin, Trusted Devices, Webhooks
// --------------------------------------------------------------------------

// AdminUsersData is the payload of GET /api/v1/admin/users.
type AdminUsersData struct {
	Items []UserProfile `json:"items"`
	Total int64         `json:"total" example:"42"`
	Page  int           `json:"page" example:"1"`
	Limit int           `json:"limit" example:"20"`
}

// AdminUsersEnvelope wraps GET /api/v1/admin/users response.
type AdminUsersEnvelope struct {
	Code    int            `json:"code" example:"200"`
	Message string         `json:"message" example:"users retrieved"`
	Data    AdminUsersData `json:"data"`
}

// AdminSessionsData is the payload of GET /api/v1/admin/sessions.
type AdminSessionsData struct {
	Sessions []SessionInfo `json:"sessions"`
}

// AdminSessionsEnvelope wraps GET /api/v1/admin/sessions response.
type AdminSessionsEnvelope struct {
	Code    int               `json:"code" example:"200"`
	Message string            `json:"message" example:"tenant sessions retrieved"`
	Data    AdminSessionsData `json:"data"`
}

// TrustedDeviceInfoData is a single trusted device projection.
type TrustedDeviceInfoData struct {
	ID         uint      `json:"id" example:"1"`
	DeviceName string    `json:"deviceName" example:"Chrome MacBook Pro"`
	IPAddress  string    `json:"ipAddress" example:"192.168.1.50"`
	ExpiresAt  time.Time `json:"expiresAt" example:"2026-10-03T18:00:00Z"`
	LastUsedAt time.Time `json:"lastUsedAt" example:"2026-09-03T18:00:00Z"`
}

// TrustedDevicesListData is the payload of GET /api/v1/auth/trusted-devices.
type TrustedDevicesListData struct {
	Devices []TrustedDeviceInfoData `json:"devices"`
}

// TrustedDevicesListEnvelope wraps GET /api/v1/auth/trusted-devices response.
type TrustedDevicesListEnvelope struct {
	Code    int                    `json:"code" example:"200"`
	Message string                 `json:"message" example:"trusted devices retrieved"`
	Data    TrustedDevicesListData `json:"data"`
}

// WebhookEndpointData is the payload of POST /api/v1/admin/webhooks.
type WebhookEndpointData struct {
	ID     string `json:"id" example:"wh_12345678"`
	URL    string `json:"url" example:"https://example.com/webhook"`
	Events string `json:"events" example:"user.created,user.locked"`
	Secret string `json:"secret" example:"sec_abcdef123456"`
}

// WebhookEndpointEnvelope wraps POST /api/v1/admin/webhooks response.
type WebhookEndpointEnvelope struct {
	Code    int                 `json:"code" example:"201"`
	Message string              `json:"message" example:"webhook endpoint created"`
	Data    WebhookEndpointData `json:"data"`
}
