// Package repositories holds the GORM-backed implementations of the
// persistence interfaces declared in the services package. Repos do NO
// business logic — just DB queries (Create, Find, Update...).
package repositories

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

// UserRepository implements services.UserRepo backed by GORM.
type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *UserRepository) FindByID(id uint) (*models.User, error) {
	var u models.User
	if err := r.db.First(&u, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	var u models.User
	if err := r.db.Where("email = ?", email).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByUsername(username string) (*models.User, error) {
	var u models.User
	if err := r.db.Where("username = ?", username).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Update(user *models.User) error {
	return r.db.Save(user).Error
}

// UpdatePassword sets a new bcrypt hash and (optionally) clears lockout state.
func (r *UserRepository) UpdatePassword(user *models.User, hashedPassword string) error {
	user.Password = hashedPassword
	return r.db.Model(user).Update("password", hashedPassword).Error
}

// IncrementFailedAttempts bumps the failed-login counter and (when lockUntil
// is non-nil) sets the lockout timestamp.
func (r *UserRepository) IncrementFailedAttempts(user *models.User, lockUntil *time.Time) error {
	user.FailedLoginAttempts++
	updates := map[string]interface{}{
		"failed_login_attempts": user.FailedLoginAttempts,
	}
	if lockUntil != nil {
		user.LockedUntil = lockUntil
		updates["locked_until"] = lockUntil
	}
	return r.db.Model(user).Updates(updates).Error
}

// ResetFailedAttempts clears the counter and lockout timestamp.
func (r *UserRepository) ResetFailedAttempts(user *models.User) error {
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	return r.db.Model(user).Updates(map[string]interface{}{
		"failed_login_attempts": 0,
		"locked_until":          nil,
	}).Error
}

func (r *UserRepository) SetEmailVerified(user *models.User, verified bool) error {
	user.IsEmailVerified = verified
	return r.db.Model(user).Update("is_email_verified", verified).Error
}
