package repositories

import (
	"context"
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

func (r *RefreshTokenRepository) Create(ctx context.Context, rt *models.RefreshToken) error {
	return r.db.WithContext(ctx).Create(rt).Error
}

// FindByHash returns the refresh-token row matching the given hash, or nil.
func (r *RefreshTokenRepository) FindByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	if err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&rt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &rt, nil
}

// FindActiveByUser returns the caller's non-expired, non-revoked sessions,
// newest activity first. Used by the "your devices / sessions" listing.
func (r *RefreshTokenRepository) FindActiveByUser(ctx context.Context, userID uint) ([]models.RefreshToken, error) {
	var rows []models.RefreshToken
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked = ? AND expires_at > ?", userID, false, time.Now()).
		Order("last_active_at DESC, id DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// RevokeByID marks a single session (scoped to userID) as revoked. The userID
// scope prevents an attacker from revoking another user's session by guessing
// ids (IDOR). Returns gorm.ErrRecordNotFound when no row matched, which the
// service maps to ErrSessionNotFound.
func (r *RefreshTokenRepository) RevokeByID(ctx context.Context, id, userID uint) error {
	res := r.db.WithContext(ctx).Model(&models.RefreshToken{}).
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

// Revoke marks the token revoked via compare-and-set: the UPDATE only matches
// while revoked = false, so of two concurrent refreshes of the same token
// exactly one wins. RowsAffected == 0 means the row was already revoked (or
// purged) — returned as ErrTokenAlreadyRevoked so callers detect the reuse.
func (r *RefreshTokenRepository) Revoke(ctx context.Context, rt *models.RefreshToken) error {
	rt.Revoked = true
	res := r.db.WithContext(ctx).Model(rt).
		Where("revoked = ?", false).
		Update("revoked", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrTokenAlreadyRevoked
	}
	return nil
}

// RevokeAllForUser revokes every active refresh token for a user — used after
// a password change to invalidate all existing sessions.
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error
}

// TouchLastActive bumps the last_active_at timestamp for a session row.
func (r *RefreshTokenRepository) TouchLastActive(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("id = ?", id).
		Update("last_active_at", time.Now()).Error
}

// PurgeExpired removes revoked/expired rows — call from a periodic cleanup.
// The old single OR-predicate delete could not use either index and ran as
// one unbounded transaction; the job now issues two indexed, LIMIT-batched
// delete streams (expired first, then revoked) so a large backlog never
// holds long locks (P1).
func (r *RefreshTokenRepository) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	db := r.db.WithContext(ctx)
	expired, err := batchedDelete(db, &models.RefreshToken{}, "expires_at < ?", before)
	if err != nil {
		return expired, err
	}
	revoked, err := batchedDelete(db, &models.RefreshToken{}, "revoked = ?", true)
	return expired + revoked, err
}
