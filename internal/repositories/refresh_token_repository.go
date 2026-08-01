package repositories

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

type RefreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Create(rt *models.RefreshToken) error {
	return r.db.Create(rt).Error
}

// FindByHash returns the refresh-token row matching the given hash, or nil.
func (r *RefreshTokenRepository) FindByHash(hash string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	if err := r.db.Where("token_hash = ?", hash).First(&rt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &rt, nil
}

func (r *RefreshTokenRepository) Revoke(rt *models.RefreshToken) error {
	rt.Revoked = true
	return r.db.Model(rt).Update("revoked", true).Error
}

// RevokeAllForUser revokes every active refresh token for a user — used after
// a password change to invalidate all existing sessions.
func (r *RefreshTokenRepository) RevokeAllForUser(userID uint) error {
	return r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error
}

// PurgeExpired removes revoked/expired rows — call from a periodic cleanup.
func (r *RefreshTokenRepository) PurgeExpired(before time.Time) (int64, error) {
	res := r.db.Where("expires_at < ? OR revoked = ?", before, true).
		Delete(&models.RefreshToken{})
	return res.RowsAffected, res.Error
}
