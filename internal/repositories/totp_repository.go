package repositories

import (
	"context"
	"errors"
	"github.com/finnapigo/finnapigo/internal/models"
	"gorm.io/gorm"
	"time"
)

type TOTPRepository struct{ db *gorm.DB }

func NewTOTPRepository(db *gorm.DB) *TOTPRepository { return &TOTPRepository{db: db} }
func (r *TOTPRepository) Upsert(ctx context.Context, d *models.TOTPDevice) error {
	return r.db.WithContext(ctx).Save(d).Error
}
func (r *TOTPRepository) FindByUserID(ctx context.Context, userID uint) (*models.TOTPDevice, error) {
	var d models.TOTPDevice
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &d, err
}
func (r *TOTPRepository) CreateRecoveryCodes(ctx context.Context, codes []*models.RecoveryCode) error {
	return r.db.WithContext(ctx).Create(codes).Error
}
func (r *TOTPRepository) ActiveRecoveryCodes(ctx context.Context, userID uint) ([]models.RecoveryCode, error) {
	var c []models.RecoveryCode
	err := r.db.WithContext(ctx).Where("user_id = ? AND used_at IS NULL", userID).Find(&c).Error
	return c, err
}
func (r *TOTPRepository) MarkRecoveryCodeUsed(ctx context.Context, c *models.RecoveryCode) error {
	now := time.Now()
	c.UsedAt = &now
	return r.db.WithContext(ctx).Model(c).Update("used_at", now).Error
}
