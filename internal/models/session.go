package models

import "time"

// Session is the server-side login-session entity (P0.3): one row per
// successful authentication (login / OAuth / passkey / MFA completion). Every
// refresh token issued by rotation carries the session's UUID in
// refresh_tokens.session_id, and every access token carries it in the `sid`
// claim — so the whole token family of one device can be revoked as a unit
// without touching the user's other devices (token-family isolation).
type Session struct {
	// ID is a UUID (v4) — never a sequential integer, so session ids leaked
	// in logs/tokens cannot be enumerated.
	ID       string `gorm:"primaryKey;size:36"                     json:"id"`
	TenantID string `gorm:"size:36;not null;default:default;index" json:"tenantId"`
	UserID   uint   `gorm:"index;not null"                         json:"userId"`

	// Device metadata captured at login and refreshed on rotation.
	IPAddress        string `gorm:"size:45" json:"ipAddress"`
	UserAgent        string `gorm:"size:500" json:"userAgent"`
	DeviceName       string `gorm:"size:120" json:"deviceName"`
	LocationEstimate string `gorm:"size:120;default:'Unknown'" json:"locationEstimate"`

	Revoked bool `gorm:"not null;default:false;index" json:"revoked"`

	LastActiveAt time.Time `json:"lastActiveAt"`
	// ExpiresAt bounds the whole family: no rotation may outlive it.
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

func (Session) TableName() string { return "sessions" }
