package models

import "time"

type TOTPDevice struct {
	ID     uint   `gorm:"primaryKey"`
	UserID uint   `gorm:"uniqueIndex;not null"`
	// Secret is kept ONLY for rows written before encrypted storage existed
	// (C7); reads fall back to it lazily and every write seals into
	// SecretEncrypted instead, leaving this blank.
	Secret string `gorm:"size:255;not null" json:"-"`
	// SecretEncrypted holds the AES-256-GCM sealed active shared secret.
	SecretEncrypted string `gorm:"size:512" json:"-"`
	// PendingSecretEncrypted stages the sealed fresh secret during
	// re-enrollment of an ACTIVE device: the old secret keeps validating
	// logins until VerifyEnable confirms the new one — re-enrollment never
	// disables MFA.
	PendingSecretEncrypted string `gorm:"size:512" json:"-"`
	Enabled                bool   `gorm:"not null;default:false"`
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type RecoveryCode struct {
	ID     uint `gorm:"primaryKey"`
	UserID uint `gorm:"index;not null"`
	// CodeHash is the SHA-256 digest used for O(1) constant-time verification
	// at login — the cheap path that never needs the plaintext back.
	CodeHash string `gorm:"size:255;not null" json:"-"`
	// CodeEncrypted holds the AES-256-GCM sealed plaintext so the user can
	// re-view their saved codes via the TOTP-gated recovery-codes endpoint.
	// It is empty for rows created before this column existed (pre-refactor
	// enrollments can regenerate to obtain a viewable set).
	CodeEncrypted string `gorm:"size:512" json:"-"`
	UsedAt        *time.Time
	CreatedAt     time.Time
}
