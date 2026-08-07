package models

import "time"

type TOTPDevice struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"uniqueIndex;not null"`
	Secret    string `gorm:"size:255;not null" json:"-"`
	Enabled   bool   `gorm:"not null;default:false"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type RecoveryCode struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"index;not null"`
	CodeHash  string `gorm:"size:255;not null" json:"-"`
	UsedAt    *time.Time
	CreatedAt time.Time
}
