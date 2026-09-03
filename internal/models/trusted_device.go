package models

import "time"

// TrustedDevice maps to the `trusted_devices` table for MFA bypass (P2.4).
type TrustedDevice struct {
	ID         uint       `gorm:"primaryKey"                   json:"id"`
	UserID     uint       `gorm:"index;not null"               json:"userId"`
	DeviceHash string     `gorm:"size:64;uniqueIndex;not null" json:"deviceHash"`
	DeviceName string     `gorm:"size:120"                     json:"deviceName"`
	IPAddress  string     `gorm:"size:45"                      json:"ipAddress"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	ExpiresAt  time.Time  `gorm:"not null"                     json:"expiresAt"`
	Revoked    bool       `gorm:"not null;default:false;index" json:"revoked"`
	CreatedAt  time.Time  `json:"createdAt"`
}

func (TrustedDevice) TableName() string { return "trusted_devices" }
