package repositories

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

// PasskeyRepository is the thin GORM persistence for WebAuthn credentials
// (W2). It holds no business rules — sign-count clone policy lives in the
// service layer.
type PasskeyRepository struct {
	db *gorm.DB
}

func NewPasskeyRepository(db *gorm.DB) *PasskeyRepository {
	return &PasskeyRepository{db: db}
}

// Create persists a freshly registered credential. The credential_id unique
// index rejects a credential already bound to any user (WebAuthn guarantees
// per-RP uniqueness; the index enforces it at rest).
func (r *PasskeyRepository) Create(ctx context.Context, pc *models.PasskeyCredential) error {
	return r.db.WithContext(ctx).Create(pc).Error
}

// FindByCredentialID returns the credential row with the given ID, or nil
// when absent. Revoked rows ARE returned — the service needs them to audit
// re-presentation of a revoked (possibly cloned) credential.
func (r *PasskeyRepository) FindByCredentialID(ctx context.Context, credentialID []byte) (*models.PasskeyCredential, error) {
	var pc models.PasskeyCredential
	err := r.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&pc).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &pc, nil
}

// ListByUser returns the caller's credentials, newest first. With
// includeRevoked=false only active (non-revoked) rows are listed (W6 device
// list); the service chooses.
func (r *PasskeyRepository) ListByUser(ctx context.Context, userID uint, includeRevoked bool) ([]models.PasskeyCredential, error) {
	var rows []models.PasskeyCredential
	q := r.db.WithContext(ctx).Where("user_id = ?", userID)
	if !includeRevoked {
		q = q.Where("revoked = ?", false)
	}
	err := q.Order("id DESC").Find(&rows).Error
	return rows, err
}

// TouchUsage updates the sign counter and last_used_at after a successful
// authentication (W5/W6).
func (r *PasskeyRepository) TouchUsage(ctx context.Context, id uint, signCount uint32, usedAt time.Time) error {
	return r.db.WithContext(ctx).Model(&models.PasskeyCredential{}).
		Where("id = ?", id).
		Updates(map[string]any{"sign_count": signCount, "last_used_at": usedAt}).Error
}

// RevokeByID marks a credential revoked via compare-and-set, scoped to the
// owning user (IDOR-safe, mirroring RefreshTokenRepository.RevokeByID).
// RowsAffected == 0 → gorm.ErrRecordNotFound (unknown id or other user's).
func (r *PasskeyRepository) RevokeByID(ctx context.Context, id, userID uint) error {
	res := r.db.WithContext(ctx).Model(&models.PasskeyCredential{}).
		Where("id = ? AND user_id = ? AND revoked = ?", id, userID, false).
		Update("revoked", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
