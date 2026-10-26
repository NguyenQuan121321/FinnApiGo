// Package identity owns the authoritative v1 access-state boundary.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/finnapigo/finnapigo/internal/database"
	"slices"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

var ErrInactive = errors.New("inactive credential")

// SecurityStore preserves failure versus absence and shared admission semantics.
type SecurityStore interface {
	Revoked(context.Context, string, string) (bool, error)
	Admit(context.Context, string, int64, time.Duration) (bool, error)
}

type Authority struct {
	DB    *gorm.DB
	Store SecurityStore
}

// Check uses a coherent durable snapshot and no positive cache. Permission sets
// must match, including empty grants; a direct DB grant removal invalidates JWTs
// even if the writer has not yet adopted the F04 epoch seam.
func (a *Authority) Check(ctx context.Context, c *jwt.Claims) error {
	if a == nil || a.DB == nil || a.Store == nil {
		return errors.New("identity dependency unavailable")
	}
	if c == nil || c.TenantID == "" || c.SID == "" || c.ID == "" {
		return ErrInactive
	}
	ctx, cancel := context.WithTimeout(tenant.WithTenant(ctx, c.TenantID), 2*time.Second)
	defer cancel()
	revoked, err := a.Store.Revoked(ctx, c.ID, c.SID)
	if err != nil {
		return err
	}
	if revoked {
		return ErrInactive
	}
	return database.FromContext(ctx, a.DB).Transaction(func(tx *gorm.DB) error {
		var u models.User
		if err := tx.Where("id = ? AND tenant_id = ?", c.UserID, c.TenantID).First(&u).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInactive
			}
			return err
		}
		if !u.IsActive || u.AdminSuspended || u.PwdVersion != c.PwdVer || u.AuthEpoch != c.AuthEpoch {
			return ErrInactive
		}
		var t models.Tenant
		if err := tx.Where("id = ?", c.TenantID).First(&t).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInactive
			}
			return err
		}
		if !t.IsActive {
			return ErrInactive
		}
		var s models.Session
		if err := tx.Where("id = ? AND tenant_id = ? AND user_id = ?", c.SID, c.TenantID, c.UserID).First(&s).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInactive
			}
			return err
		}
		if s.Revoked || !time.Now().Before(s.ExpiresAt) {
			return ErrInactive
		}
		var n int64
		if err := tx.Model(&models.AccessRevocation{}).Where("tenant_id = ? AND jti = ?", c.TenantID, c.ID).Count(&n).Error; err != nil {
			return err
		}
		if n != 0 {
			return ErrInactive
		}
		perms, err := repositories.NewRBACRepository(tx).GetUserPermissions(ctx, c.UserID)
		if err != nil {
			return err
		}
		actual, signed := slices.Clone(perms), slices.Clone(c.Permissions)
		slices.Sort(actual)
		slices.Sort(signed)
		if !slices.Equal(slices.Compact(actual), slices.Compact(signed)) {
			return ErrInactive
		}
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
}

// RevokeAccess durably records a tenant/JTI denial before acknowledging logout.
// F04 owns the remaining multi-step family and refresh containment lifecycle.
func (a *Authority) RevokeAccess(ctx context.Context, jti string, exp time.Time) error {
	if jti == "" {
		return ErrInactive
	}
	return database.FromContext(ctx, a.DB).Clauses(clause.OnConflict{DoNothing: true}).Create(&models.AccessRevocation{
		TenantID: tenant.FromContext(ctx), JTI: jti, ExpiresAt: exp,
	}).Error
}

// Suspend is the durable account/session seam for F04. It is deliberately not
// exposed as a new public admin API or a claim of complete refresh containment.
func (a *Authority) Suspend(ctx context.Context, uid uint) error {
	tid := tenant.FromContext(ctx)
	return database.FromContext(ctx, a.DB).Transaction(func(tx *gorm.DB) error {
		r := tx.Model(&models.User{}).Where("id = ? AND tenant_id = ?", uid, tid).Updates(map[string]any{
			"admin_suspended": true, "auth_epoch": gorm.Expr("auth_epoch + 1"), "pwd_version": gorm.Expr("pwd_version + 1"),
		})
		if r.Error != nil {
			return r.Error
		}
		if r.RowsAffected != 1 {
			return ErrInactive
		}
		return tx.Model(&models.Session{}).Where("user_id = ? AND tenant_id = ?", uid, tid).Update("revoked", true).Error
	})
}
