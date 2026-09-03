package models

import "time"

// Tenant maps to the `tenants` table for multi-tenant isolation (P2.1).
type Tenant struct {
	ID        string    `gorm:"primaryKey;size:36"           json:"id"`
	Slug      string    `gorm:"size:64;uniqueIndex;not null" json:"slug"`
	Name      string    `gorm:"size:255;not null"            json:"name"`
	IsActive  bool      `gorm:"not null;default:true"        json:"isActive"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (Tenant) TableName() string { return "tenants" }
