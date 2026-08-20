package repositories

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

// UsedTokenRepository records consumed single-use JWTs (reset/verify) and
// answers "has this jti been used?". It is the durability backstop for the
// Store-based check used in the hot path (§1.8).
type UsedTokenRepository struct {
	db *gorm.DB
}

func NewUsedTokenRepository(db *gorm.DB) *UsedTokenRepository {
	return &UsedTokenRepository{db: db}
}

// MarkUsed atomically records a jti. If the jti already exists it returns
// false (already consumed) — used to reject token replay.
func (r *UsedTokenRepository) MarkUsed(ctx context.Context, jti, tokenType string, userID uint, exp time.Time) (bool, error) {
	row := &models.UsedToken{
		JTI: jti, TokenType: tokenType, UserID: userID, ExpiresAt: exp,
	}
	err := r.db.WithContext(ctx).Create(row).Error
	if err != nil {
		if isGormDuplicate(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// IsUsed reports whether the jti has been consumed.
func (r *UsedTokenRepository) IsUsed(ctx context.Context, jti string) (bool, error) {
	var row models.UsedToken
	err := r.db.WithContext(ctx).Where("jti = ?", jti).First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// PurgeExpired removes used-token rows past their original JWT expiry — they
// can no longer be replayed once the JWT itself is expired, so keeping them
// forever is pointless. Deletes run in LIMIT-batched statements against the
// expires_at index (P1).
func (r *UsedTokenRepository) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	return batchedDelete(r.db.WithContext(ctx), &models.UsedToken{}, "expires_at < ?", before)
}
