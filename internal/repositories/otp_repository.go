package repositories

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

type OtpRepository struct {
	db *gorm.DB
}

func NewOtpRepository(db *gorm.DB) *OtpRepository {
	return &OtpRepository{db: db}
}

func (r *OtpRepository) Create(ctx context.Context, o *models.OtpCode) error {
	return r.db.WithContext(ctx).Create(o).Error
}

// FindLatestActive returns the newest unused, non-expired OTP for the user+purpose.
func (r *OtpRepository) FindLatestActive(ctx context.Context, userID uint, purpose string) (*models.OtpCode, error) {
	var o models.OtpCode
	err := r.db.WithContext(ctx).Where("user_id = ? AND purpose = ? AND is_used = ? AND expires_at > ?",
		userID, purpose, false, time.Now()).
		Order("created_at DESC").
		First(&o).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &o, nil
}

func (r *OtpRepository) Update(ctx context.Context, o *models.OtpCode) error {
	return r.db.WithContext(ctx).Save(o).Error
}

// MarkUsed flags an OTP as consumed.
func (r *OtpRepository) MarkUsed(ctx context.Context, o *models.OtpCode) error {
	o.IsUsed = true
	return r.db.WithContext(ctx).Model(o).Update("is_used", true).Error
}

// IncrementAttempts bumps the attempt counter. Returns the new count.
func (r *OtpRepository) IncrementAttempts(ctx context.Context, o *models.OtpCode) (int, error) {
	o.AttemptCount++
	if err := r.db.WithContext(ctx).Model(o).Update("attempt_count", o.AttemptCount).Error; err != nil {
		return 0, err
	}
	return o.AttemptCount, nil
}

// PurgeExpired removes used/expired OTP rows — call from a periodic cleanup.
func (r *OtpRepository) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).Where("expires_at < ? OR is_used = ?", before, true).
		Delete(&models.OtpCode{})
	return res.RowsAffected, res.Error
}
