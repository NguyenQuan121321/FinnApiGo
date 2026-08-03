package models

import "time"

// RefreshToken stores ONLY the SHA-256 hash of the issued refresh token.
// The plaintext token is returned to the client once and never persisted,
// so a DB leak does not expose valid tokens.
type RefreshToken struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index;not null" json:"userId"`
	TokenHash string    `gorm:"size:64;uniqueIndex;not null" json:"-"` // sha256 hex = 64 chars
	ExpiresAt time.Time `gorm:"not null" json:"expiresAt"`
	Revoked   bool      `gorm:"not null;default:false" json:"revoked"`
	// §4 — Device/IP metadata for audit trail. Nullable so existing rows
	// are unaffected by the migration.
	IPAddress string     `gorm:"size:45" json:"ipAddress"`
	UserAgent string     `gorm:"size:500" json:"userAgent"`
	CreatedAt time.Time  `json:"createdAt"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }
