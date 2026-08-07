package models

import "time"

// Audit event constants.
const (
	AuditEventLogin               = "login"
	AuditEventLoginFailed         = "login_failed"
	AuditEventLogout              = "logout"
	AuditEventPasswordChanged     = "password_changed"
	AuditEventPasswordReset       = "password_reset"
	AuditEventOTPSent             = "otp_sent"
	AuditEventOTPVerified         = "otp_verified"
	AuditEventRefreshToken        = "refresh_token"
	AuditEventTokenReuse          = "token_reuse"
	AuditEventVerifyResendBlocked = "verify_resend_blocked" // §7.6.3 — anti-automation event
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
