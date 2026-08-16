package models

import "time"

// UsedToken records a consumed single-use JWT (reset-password / verify-email)
// by its jti (JWT ID). It enforces single-use semantics for otherwise-stateless
// JWTs, mirroring the refresh-token single-use guarantee (§1.8).
//
// Lookups also go through the Store abstraction (SetNX) for the hot path, so
// multi-instance correctness doesn't depend on DB row visibility timing; this
// table exists for durability and backstop auditing.
type UsedToken struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	JTI       string    `gorm:"size:64;uniqueIndex;not null" json:"jti"`
	TokenType string    `gorm:"size:20;not null" json:"tokenType"`
	UserID    uint      `gorm:"index" json:"userId"`
	// ExpiresAt is indexed for the purge job's batched deletes (P1).
	ExpiresAt time.Time `gorm:"not null;index" json:"expiresAt"`
	CreatedAt time.Time `gorm:"index" json:"createdAt"`
}

func (UsedToken) TableName() string { return "used_tokens" }
