package models

import "time"

// Permission represents a fine-grained capability in the RBAC system (P2.2).
type Permission struct {
	ID          uint      `gorm:"primaryKey"                    json:"id"`
	Name        string    `gorm:"size:100;uniqueIndex;not null" json:"name"`
	Description string    `gorm:"size:255"                      json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

func (Permission) TableName() string { return "permissions" }

// Role is a tenant-scoped collection of permissions (P2.2).
type Role struct {
	ID          uint         `gorm:"primaryKey"                                                    json:"id"`
	TenantID    string       `gorm:"size:36;not null;default:default;uniqueIndex:idx_roles_tenant_name;index" json:"tenantId"`
	Name        string       `gorm:"size:50;not null;uniqueIndex:idx_roles_tenant_name"             json:"name"`
	Description string       `gorm:"size:255"                                                      json:"description"`
	Permissions []Permission `gorm:"many2many:role_permissions;"                                  json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"createdAt"`
	UpdatedAt   time.Time    `json:"updatedAt"`
}

func (Role) TableName() string { return "roles" }

// RolePermission maps a role to a permission.
type RolePermission struct {
	RoleID       uint `gorm:"primaryKey" json:"roleId"`
	PermissionID uint `gorm:"primaryKey" json:"permissionId"`
}

func (RolePermission) TableName() string { return "role_permissions" }

// UserRole assigns a tenant role to a user.
type UserRole struct {
	UserID uint `gorm:"primaryKey" json:"userId"`
	RoleID uint `gorm:"primaryKey" json:"roleId"`
}

func (UserRole) TableName() string { return "user_roles" }
