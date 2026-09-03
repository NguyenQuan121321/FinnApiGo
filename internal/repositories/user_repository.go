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
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// UserRepository implements services.UserRepo backed by GORM.
type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	if user.TenantID == "" {
		user.TenantID = tenant.FromContext(ctx)
	}
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *UserRepository) FindByID(ctx context.Context, id uint) (*models.User, error) {
	var u models.User
	tid := tenant.FromContext(ctx)
	q := r.db.WithContext(ctx).Where("id = ?", id)
	if tid != "" && tid != tenant.DefaultTenantID {
		q = q.Where("tenant_id = ?", tid)
	}
	if err := q.First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var u models.User
	tid := tenant.FromContext(ctx)
	q := r.db.WithContext(ctx).Where("email = ?", email)
	if tid != "" {
		q = q.Where("tenant_id = ?", tid)
	}
	if err := q.First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var u models.User
	tid := tenant.FromContext(ctx)
	q := r.db.WithContext(ctx).Where("username = ?", username)
	if tid != "" {
		q = q.Where("tenant_id = ?", tid)
	}
	if err := q.First(&u).Error; err != nil {
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

// BumpPwdVersion increments the credential-version counter in SQL (atomic —
// concurrent changes must both land). Access tokens carrying an older
// version are rejected afterwards (A7).
func (r *UserRepository) BumpPwdVersion(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).
		Update("pwd_version", gorm.Expr("pwd_version + 1")).Error
}

// CredentialChangeTx applies the ENTIRE credential-change sequence as ONE
// transaction: password hash, lockout reset, pwd-version bump (A7), and the
// caller-supplied refresh-token revocation. Without the transaction, a crash
// between the UPDATEs could leave the password changed while an attacker's
// refresh tokens survive — the exact state a password change exists to end.
// Implements services.TransactionalCredentialChanger.
func (r *UserRepository) CredentialChangeTx(ctx context.Context, userID uint, hashedPassword string, revokeRefresh func(tx *gorm.DB) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.User{}).
			Where("id = ?", userID).
			Updates(map[string]interface{}{
				"password":              hashedPassword,
				"failed_login_attempts": 0,
				"locked_until":          nil,
				"pwd_version":           gorm.Expr("pwd_version + 1"),
			}).Error; err != nil {
			return err
		}
		return revokeRefresh(tx)
	})
}

// SetFirstPassword sets the password hash ONLY while the account has none
// (conditional UPDATE on password = ”). Returns false when the account
// already has a password — including when a concurrent setter won the race —
// so the check-then-act window in SetPassword is closed.
// Implements services.FirstPasswordSetter.
func (r *UserRepository) SetFirstPassword(ctx context.Context, userID uint, hashedPassword string) (bool, error) {
	res := r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND password = ?", userID, "").
		Update("password", hashedPassword)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *UserRepository) SetEmailVerified(ctx context.Context, user *models.User, verified bool) error {
	user.IsEmailVerified = verified
	return r.db.WithContext(ctx).Model(user).Update("is_email_verified", verified).Error
}

// ListPaginated retrieves users within a tenant with optional search filter (P2.3 admin).
func (r *UserRepository) ListPaginated(ctx context.Context, tenantID string, page, limit int, search string) ([]models.User, int64, error) {
	if tenantID == "" {
		tenantID = tenant.FromContext(ctx)
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit
	var total int64
	q := r.db.WithContext(ctx).Model(&models.User{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	if search != "" {
		searchTerm := "%" + search + "%"
		q = q.Where("username LIKE ? OR email LIKE ? OR full_name LIKE ?", searchTerm, searchTerm, searchTerm)
	}
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var users []models.User
	err := q.Order("id DESC").Offset(offset).Limit(limit).Find(&users).Error
	return users, total, err
}

// SetLock sets or clears the lockout timestamp and resets failed attempts on unlock (P2.3 admin).
func (r *UserRepository) SetLock(ctx context.Context, userID uint, lockedUntil *time.Time) error {
	updates := map[string]any{
		"locked_until": lockedUntil,
	}
	if lockedUntil == nil {
		updates["failed_login_attempts"] = 0
	}
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).
		Updates(updates).Error
}
