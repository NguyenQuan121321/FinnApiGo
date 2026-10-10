package repositories

import (
	"context"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"gorm.io/gorm"
)

// ownedRows scopes tables without tenant_id through their authoritative owner.
// Caller-supplied object IDs never select a different tenant.
func ownedRows(db *gorm.DB, ctx context.Context) *gorm.DB {
	return db.WithContext(ctx).Where("user_id IN (?)", db.WithContext(ctx).
		Model(&models.User{}).Select("id").Where("tenant_id = ?", tenant.FromContext(ctx)))
}

func requireOwner(db *gorm.DB, ctx context.Context, userID uint) error {
	var count int64
	if err := db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND tenant_id = ?", userID, tenant.FromContext(ctx)).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func scopeTenant(ctx context.Context, requested string) (string, error) {
	tid := tenant.FromContext(ctx)
	if requested != "" && requested != tid {
		return "", gorm.ErrRecordNotFound
	}
	return tid, nil
}

// updateScoped never upserts. MySQL can report zero changed rows for an
// idempotent update, so distinguish that from a missing scoped record.
func updateScoped(q *gorm.DB, values any) error {
	res := q.Session(&gorm.Session{}).Updates(values)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		var count int64
		if err := q.Session(&gorm.Session{}).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return gorm.ErrRecordNotFound
		}
	}
	return nil
}
