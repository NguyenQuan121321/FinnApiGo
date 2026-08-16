package models

import "time"

// Audit event constants.
const (
	AuditEventLogin                    = "login"
	AuditEventLoginFailed              = "login_failed"
	AuditEventLogout                   = "logout"
	AuditEventPasswordChanged          = "password_changed"
	AuditEventPasswordReset            = "password_reset"
	AuditEventPasswordSet              = "password_set" // first password established (OAuth-only account)
	AuditEventOTPSent                  = "otp_sent"
	AuditEventOTPVerified              = "otp_verified"
	AuditEventRefreshToken             = "refresh_token"
	AuditEventTokenReuse               = "token_reuse"
	AuditEventVerifyResendBlocked      = "verify_resend_blocked" // §7.6.3 — anti-automation event
	AuditEventTOTPEnabled              = "totp_enabled"
	AuditEventTOTPValidated            = "totp_validated"
	AuditEventTOTPFailed               = "totp_failed"
	AuditEventRecoveryCodeUsed         = "recovery_code_used"
	AuditEventRecoveryCodesViewed      = "recovery_codes_viewed"      // user re-viewed saved codes (grants sudo)
	AuditEventRecoveryCodesRegenerated = "recovery_codes_regenerated" // old set invalidated, new set issued
	AuditEventSessionRevoked           = "session_revoked"            // user revoked a single device/session
)

// AuditLog records security-relevant actions for compliance / forensics.
// Writing here is best-effort: an audit failure must never break a request.
type AuditLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    *uint     `gorm:"index" json:"userId"`   // nil if pre-auth
	Email     string    `gorm:"size:255" json:"email"` // identity hint pre-login
	Event     string    `gorm:"size:40;index;not null" json:"event"`
	IPAddress string    `gorm:"size:45" json:"ipAddress"`
	Success   bool      `gorm:"not null;default:false" json:"success"`
	Detail    string    `gorm:"size:500" json:"detail"`
	CreatedAt time.Time `gorm:"index" json:"createdAt"`
}

func (AuditLog) TableName() string { return "audit_logs" }
