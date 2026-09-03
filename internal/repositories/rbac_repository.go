package repositories

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// RBACRepository persists permissions, roles, and user role assignments (P2.2).
type RBACRepository struct {
	db *gorm.DB
}

func NewRBACRepository(db *gorm.DB) *RBACRepository {
	return &RBACRepository{db: db}
}

// ListPermissions returns all available system permissions.
func (r *RBACRepository) ListPermissions(ctx context.Context) ([]models.Permission, error) {
	var perms []models.Permission
	err := r.db.WithContext(ctx).Order("name ASC").Find(&perms).Error
	return perms, err
}

// CreateRole inserts a new role scoped to the tenant with assigned permission names.
func (r *RBACRepository) CreateRole(ctx context.Context, role *models.Role, permNames []string) error {
	if role.TenantID == "" {
		role.TenantID = tenant.FromContext(ctx)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(role).Error; err != nil {
			return err
		}

		if len(permNames) > 0 {
			var perms []models.Permission
			if err := tx.Where("name IN ?", permNames).Find(&perms).Error; err != nil {
				return err
			}
			for _, p := range perms {
				rp := models.RolePermission{
					RoleID:       role.ID,
					PermissionID: p.ID,
				}
				if err := tx.Create(&rp).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// AssignRoleToUser associates a role with a user.
func (r *RBACRepository) AssignRoleToUser(ctx context.Context, userID, roleID uint) error {
	ur := models.UserRole{UserID: userID, RoleID: roleID}
	return r.db.WithContext(ctx).Create(&ur).Error
}

// GetUserPermissions returns all permission names granted to a user across all their roles.
func (r *RBACRepository) GetUserPermissions(ctx context.Context, userID uint) ([]string, error) {
	var permNames []string
	err := r.db.WithContext(ctx).Table("permissions").
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ?", userID).
		Distinct("permissions.name").
		Pluck("permissions.name", &permNames).Error
	return permNames, err
}

// UserHasPermission checks whether a user holds a specific permission name.
func (r *RBACRepository) UserHasPermission(ctx context.Context, userID uint, permission string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Table("permissions").
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ? AND permissions.name = ?", userID, permission).
		Count(&count).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return count > 0, nil
}
