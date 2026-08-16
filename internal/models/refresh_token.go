package models

import "time"

// RefreshToken stores ONLY the SHA-256 hash of the issued refresh token.
// The plaintext token is returned to the client once and never persisted,
// so a DB leak does not expose valid tokens.
//
// Each row doubles as a "session/device" record: the device/IP metadata
// fields let the user inspect active devices and revoke an individual
// session (see §Session & Device Management).
type RefreshToken struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index;not null" json:"userId"`
	TokenHash string    `gorm:"size:64;uniqueIndex;not null" json:"-"` // sha256 hex = 64 chars
	// ExpiresAt/Revoked carry the indexes backing the batched purge job's
	// split predicates (P1) — no table scan over live sessions.
	ExpiresAt time.Time `gorm:"not null;index" json:"expiresAt"`
	Revoked   bool      `gorm:"not null;default:false;index" json:"revoked"`

	// ---- Device/IP metadata for session management (§4) ----
	// Nullable so existing rows are unaffected by the migration.
	IPAddress  string `gorm:"size:45" json:"ipAddress"`   // caller's IP (IPv4/IPv6)
	UserAgent  string `gorm:"size:500" json:"userAgent"`  // raw User-Agent header
	DeviceName string `gorm:"size:120" json:"deviceName"` // human-readable e.g. "Chrome on Windows"

	// LocationEstimate is a best-effort geo label derived from the IP at login.
	// Defaults to "Unknown" when no resolver is configured / offline.
	LocationEstimate string `gorm:"size:120;default:'Unknown'" json:"locationEstimate"`

	// LastActiveAt is bumped whenever this session is used (issued, verified,
	// or rotated). Lets the user see "last seen 2 minutes ago" per device.
	LastActiveAt time.Time `json:"lastActiveAt"`

	CreatedAt time.Time `json:"createdAt"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }
