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
	AuditEventVerifyEmailSendFailed    = "verify_email_send_failed"   // account persisted but the verification email did not (C11)
	AuditEventRegisterDuplicate        = "register_duplicate"         // P0.1 — registration replayed an existing email/username (neutral 201 + owner notification)
	AuditEventAccessTokenRevoked       = "access_token_revoked"       // P0.2 — a logout denylisted the caller's access token jti
	AuditEventTOTPDisabled             = "totp_disabled"              // P1.1 — MFA device turned off (sudo/password gated)
	AuditEventEmailChangeRequested     = "email_change_requested"     // P1.2 — staged change-email request
	AuditEventEmailChanged             = "email_changed"              // P1.2 — change-email confirmed
	AuditEventAccountDeactivated       = "account_deactivated"        // P1.3 — self-deactivation
	AuditEventAccountErased            = "account_erased"             // P1.3 — GDPR erase (anonymized)
	AuditEventOAuthLinked              = "oauth_linked"               // P1.6 — OAuth identity linked to the account
	AuditEventOAuthUnlinked            = "oauth_unlinked"             // P1.6 — OAuth identity unlinked
	AuditEventTrustedDeviceUsed        = "trusted_device_used"        // P2.4 — remembered device skipped MFA
	AuditEventTrustedDeviceRevoked     = "trusted_device_revoked"     // P2.4 — remembered device revoked
	AuditEventWebhookDeliveryFailed    = "webhook_delivery_failed"    // P2.5 — outbox delivery exhausted retries
	AuditEventAdminAction              = "admin_action"               // P2.3 — privileged admin operation
)

// AuditLog records security-relevant actions for compliance / forensics.
// Writing here is best-effort: an audit failure must never break a request.
type AuditLog struct {
	ID         uint      `gorm:"primaryKey"                     json:"id"`
	TenantID   string    `gorm:"size:36;not null;default:default;index" json:"tenantId"`
	UserID     *uint     `gorm:"index"                          json:"userId"` // nil if pre-auth
	Email      string    `gorm:"size:255"                       json:"email"`  // identity hint pre-login
	Event      string    `gorm:"size:40;index;not null"         json:"event"`
	IPAddress  string    `gorm:"size:45"                        json:"ipAddress"`
	Success    bool      `gorm:"not null;default:false"         json:"success"`
	Detail     string    `gorm:"size:500"                       json:"detail"`
	PrevHash   string    `gorm:"size:64"                        json:"prevHash,omitempty"`   // P2.6 hash-chain
	RecordHash string    `gorm:"size:64"                        json:"recordHash,omitempty"` // P2.6 tamper-evident HMAC
	CreatedAt  time.Time `gorm:"index"                          json:"createdAt"`
}

func (AuditLog) TableName() string { return "audit_logs" }
