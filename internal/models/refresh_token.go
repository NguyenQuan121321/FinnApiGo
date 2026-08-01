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
	CreatedAt time.Time `json:"createdAt"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }
