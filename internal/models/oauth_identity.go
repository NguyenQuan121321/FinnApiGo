// Package models defines the GORM entity structs (database tables).
package models

import "time"

// OAuthIdentity stores a third-party OAuth link for a user.
// One user can have multiple identities (e.g. google + github), and each
// (provider, provider_user_id) pair is globally unique — a single Google
// account cannot be linked to two different local users.
type OAuthIdentity struct {
	ID             uint      `gorm:"primaryKey"                                      json:"id"`
	UserID         uint      `gorm:"not null;index"                                   json:"userId"`
	Provider       string    `gorm:"size:20;not null;uniqueIndex:idx_oauth_prov_uid" json:"provider"`
	ProviderUserID string    `gorm:"size:255;not null;uniqueIndex:idx_oauth_prov_uid" json:"providerUserId"`
	CreatedAt      time.Time `json:"createdAt"`
}

func (OAuthIdentity) TableName() string { return "oauth_identities" }
