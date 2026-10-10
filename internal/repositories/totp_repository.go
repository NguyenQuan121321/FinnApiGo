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
	if err := requireOwner(r.db, ctx, d.UserID); err != nil {
		return err
	}
	if d.ID == 0 {
		return r.db.WithContext(ctx).Create(d).Error
	}
	return updateScoped(ownedRows(r.db, ctx).Model(&models.TOTPDevice{}).Where("id = ? AND user_id = ?", d.ID, d.UserID).Select("*").Omit("id", "user_id", "created_at"), d)
}
func (r *TOTPRepository) FindByUserID(ctx context.Context, userID uint) (*models.TOTPDevice, error) {
	var d models.TOTPDevice
	err := ownedRows(r.db, ctx).Where("user_id = ?", userID).First(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &d, err
}

// Disable marks the user's TOTP device as disabled and clears secrets (P1.1).
func (r *TOTPRepository) Disable(ctx context.Context, userID uint) error {
	if err := requireOwner(r.db, ctx, userID); err != nil {
		return err
	}
	return ownedRows(r.db, ctx).Model(&models.TOTPDevice{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"enabled":                  false,
			"secret":                   "",
			"secret_encrypted":         "",
			"pending_secret_encrypted": "",
			"updated_at":               time.Now(),
		}).Error
}

// ReplaceRecoveryCodes atomically swaps the user's entire recovery-code set:
// all existing rows (used and unused) are deleted and the new batch inserted
// within one transaction, so a regenerate can never leave a mixed old/new set
// or drop the user to zero codes if the insert fails.
func (r *TOTPRepository) ReplaceRecoveryCodes(ctx context.Context, userID uint, codes []*models.RecoveryCode) error {
	if err := requireOwner(r.db, ctx, userID); err != nil {
		return err
	}
	for _, c := range codes {
		if c.UserID != userID {
			return gorm.ErrRecordNotFound
		}
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ownedRows(tx, ctx).Where("user_id = ?", userID).Delete(&models.RecoveryCode{}).Error; err != nil {
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
	err := ownedRows(r.db, ctx).Where("user_id = ? AND used_at IS NULL", userID).Find(&c).Error
	return c, err
}

// MarkRecoveryCodeUsed marks the code consumed via compare-and-set
// (WHERE used_at IS NULL): concurrent submissions of one code yield exactly
// one winner; the loser gets ErrRecoveryCodeUsed.
func (r *TOTPRepository) MarkRecoveryCodeUsed(ctx context.Context, c *models.RecoveryCode) error {
	now := time.Now()
	res := ownedRows(r.db, ctx).Model(c).
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
