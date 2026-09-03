package repositories

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

// TrustedDeviceRepository persists trusted devices for MFA bypass (P2.4).
type TrustedDeviceRepository struct {
	db *gorm.DB
}

func NewTrustedDeviceRepository(db *gorm.DB) *TrustedDeviceRepository {
	return &TrustedDeviceRepository{db: db}
}

func (r *TrustedDeviceRepository) Create(ctx context.Context, d *models.TrustedDevice) error {
	return r.db.WithContext(ctx).Create(d).Error
}

func (r *TrustedDeviceRepository) FindByDeviceHash(ctx context.Context, hash string) (*models.TrustedDevice, error) {
	var d models.TrustedDevice
	err := r.db.WithContext(ctx).
		Where("device_hash = ? AND revoked = ? AND expires_at > ?", hash, false, time.Now()).
		First(&d).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &d, nil
}

func (r *TrustedDeviceRepository) TouchUsage(ctx context.Context, id uint, at time.Time) error {
	return r.db.WithContext(ctx).Model(&models.TrustedDevice{}).
		Where("id = ?", id).
		Update("last_used_at", at).Error
}

func (r *TrustedDeviceRepository) ListByUser(ctx context.Context, userID uint) ([]models.TrustedDevice, error) {
	var rows []models.TrustedDevice
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked = ? AND expires_at > ?", userID, false, time.Now()).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *TrustedDeviceRepository) Revoke(ctx context.Context, id, userID uint) error {
	res := r.db.WithContext(ctx).Model(&models.TrustedDevice{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("revoked", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
