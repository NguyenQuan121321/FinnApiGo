// Package repositories holds the GORM-backed implementations of the
// persistence interfaces declared in the services package. Repos do NO
// business logic — just DB queries (Create, Find, Update...).
//
// Every method takes a context.Context as its first parameter and threads it
// into GORM via WithContext(ctx). This lets request deadlines and client
// disconnects cancel in-flight DB queries instead of consuming a pool
// connection until completion (§1.4).
package repositories

import (
	"context"
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

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *UserRepository) FindByID(ctx context.Context, id uint) (*models.User, error) {
	var u models.User
	if err := r.db.WithContext(ctx).First(&u, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var u models.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var u models.User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// UpdatePassword sets a new bcrypt hash and (optionally) clears lockout state.
func (r *UserRepository) UpdatePassword(ctx context.Context, user *models.User, hashedPassword string) error {
	user.Password = hashedPassword
	return r.db.WithContext(ctx).Model(user).Update("password", hashedPassword).Error
}

// IncrementFailedAttempts bumps the failed-login counter and (when lockUntil
// is non-nil) sets the lockout timestamp. The counter bump runs as SQL
// (failed_login_attempts + 1), never as a value computed from the in-memory
// struct — parallel failures from stale snapshots must all persist or the
// lockout threshold can be evaded (C3).
func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, user *models.User, lockUntil *time.Time) error {
	user.FailedLoginAttempts++
	updates := map[string]interface{}{
		"failed_login_attempts": gorm.Expr("failed_login_attempts + 1"),
	}
	if lockUntil != nil {
		user.LockedUntil = lockUntil
		updates["locked_until"] = lockUntil
	}
	return r.db.WithContext(ctx).Model(user).Updates(updates).Error
}

// ResetFailedAttempts clears the counter and lockout timestamp.
func (r *UserRepository) ResetFailedAttempts(ctx context.Context, user *models.User) error {
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	return r.db.WithContext(ctx).Model(user).Updates(map[string]interface{}{
		"failed_login_attempts": 0,
		"locked_until":          nil,
	}).Error
}

func (r *UserRepository) SetEmailVerified(ctx context.Context, user *models.User, verified bool) error {
	user.IsEmailVerified = verified
	return r.db.WithContext(ctx).Model(user).Update("is_email_verified", verified).Error
}
