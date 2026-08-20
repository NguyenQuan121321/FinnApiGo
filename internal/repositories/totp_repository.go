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

// ReplaceRecoveryCodes atomically swaps the user's entire recovery-code set:
// all existing rows (used and unused) are deleted and the new batch inserted
// within one transaction, so a regenerate can never leave a mixed old/new set
// or drop the user to zero codes if the insert fails.
func (r *TOTPRepository) ReplaceRecoveryCodes(ctx context.Context, userID uint, codes []*models.RecoveryCode) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&models.RecoveryCode{}).Error; err != nil {
			return err
		}
		if len(codes) == 0 {
			return nil
		}
		return tx.Create(codes).Error
	})
}
func (r *TOTPRepository) ActiveRecoveryCodes(ctx context.Context, userID uint) ([]models.RecoveryCode, error) {
	var c []models.RecoveryCode
	err := r.db.WithContext(ctx).Where("user_id = ? AND used_at IS NULL", userID).Find(&c).Error
	return c, err
}

// MarkRecoveryCodeUsed marks the code consumed via compare-and-set
// (WHERE used_at IS NULL): concurrent submissions of one code yield exactly
// one winner; the loser gets ErrRecoveryCodeUsed.
func (r *TOTPRepository) MarkRecoveryCodeUsed(ctx context.Context, c *models.RecoveryCode) error {
	now := time.Now()
	res := r.db.WithContext(ctx).Model(c).
		Where("used_at IS NULL").
		Update("used_at", now)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrRecoveryCodeUsed
	}
	c.UsedAt = &now
	return nil
}
