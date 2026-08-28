package models

import "time"

// PasskeyCredential is one registered WebAuthn authenticator (W1). The
// credential ID and COSE public key are stored raw; the credential ID is
// globally unique per the WebAuthn spec. Transports is a JSON array string
// (e.g. `["internal","hybrid"]`). Revoked rows stay for clone-detection
// forensics — a revoked credential can never authenticate again (W5).
type PasskeyCredential struct {
	ID     uint `gorm:"primaryKey" json:"id"`
	UserID uint `gorm:"not null;index" json:"userId"`

	CredentialID []byte `gorm:"type:varbinary(512);uniqueIndex;not null" json:"-"` // secret-ish: never echoed
	PublicKey    []byte `gorm:"type:blob;not null" json:"-"`
	SignCount    uint32 `gorm:"not null;default:0" json:"-"`

	DisplayName     string `gorm:"size:255" json:"displayName"`
	Transports      string `gorm:"type:json" json:"transports"`
	AttestationType string `gorm:"size:64" json:"attestationType"`

	LastUsedAt *time.Time `json:"lastUsedAt"`
	Revoked    bool       `gorm:"not null;default:false;index" json:"revoked"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (PasskeyCredential) TableName() string { return "passkey_credentials" }

// Audit event constants for the passkey ceremonies (W5).
const (
	AuditEventPasskeyRegistered     = "passkey_registered"
	AuditEventPasskeyLogin          = "passkey_login"
	AuditEventWebAuthnCloneDetected = "passkey.clone_detected"
	AuditEventPasskeyRevoked        = "passkey_revoked"
)
