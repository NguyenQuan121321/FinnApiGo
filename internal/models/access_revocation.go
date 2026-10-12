package models

import "time"

// AccessRevocation is durable security state, not an evictable cache entry.
type AccessRevocation struct {
	TenantID  string    `gorm:"primaryKey;size:36"`
	JTI       string    `gorm:"primaryKey;size:64"`
	ExpiresAt time.Time `gorm:"not null;index"`
}

func (AccessRevocation) TableName() string { return "access_revocations" }
