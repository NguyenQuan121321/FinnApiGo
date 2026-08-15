// Package models defines the GORM entity structs (database tables).
package models

import "time"

// Role constants — referenced by RequireRole middleware and seed data.
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// User maps to the `users` table.
//
// Notes vs. the prompt's minimum field list:
//   - password holds a BCRYPT HASH, never plaintext.
//   - locked_until supports temporary lockouts (a timestamp), distinct from
//     is_active, which represents a permanent enable/disable state. The prompt
//     requires "temporary lock" semantics, which cannot be expressed with a
//     single boolean is_active field.
type User struct {
	ID                  uint       `gorm:"primaryKey"           json:"id"`
	Username            string     `gorm:"size:50;uniqueIndex;not null" json:"username"`
	Email               string     `gorm:"size:255;uniqueIndex;not null" json:"email"`
	Password            string     `gorm:"size:255;not null"           json:"-"` // never serialized
	FullName            string     `gorm:"size:255"                    json:"fullName"`
	Role                string     `gorm:"size:20;not null;default:user" json:"role"`
	IsActive            bool       `gorm:"not null;default:true"       json:"isActive"`
	IsEmailVerified     bool       `gorm:"not null;default:false"      json:"isEmailVerified"`
	FailedLoginAttempts int        `gorm:"not null;default:0"          json:"-"`
	LockedUntil         *time.Time `json:"-"` // nil = not locked
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`
}

func (User) TableName() string { return "users" }
