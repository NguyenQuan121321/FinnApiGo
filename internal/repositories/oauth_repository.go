// Package repositories provides GORM-backed implementations of the service-layer
// repository interfaces. Each struct holds a *gorm.DB and translates interface
// calls into GORM queries.
package repositories

import (
	"context"
	"errors"

	"github.com/finnapigo/finnapigo/internal/models"
	"gorm.io/gorm"
)

// OAuthIdentityRepository persists OAuth identity links in the oauth_identities
// table. Each row maps a (provider, provider_user_id) pair to a local user.
type OAuthIdentityRepository struct {
	db *gorm.DB
}

// NewOAuthIdentityRepository constructs a repository backed by the given GORM DB.
func NewOAuthIdentityRepository(db *gorm.DB) *OAuthIdentityRepository {
	return &OAuthIdentityRepository{db: db}
}

// Create inserts a new OAuth identity link. Duplicate (provider, provider_user_id)
// rows are rejected by the DB-level unique index.
func (r *OAuthIdentityRepository) Create(ctx context.Context, identity *models.OAuthIdentity) error {
	return r.db.WithContext(ctx).Create(identity).Error
}

// FindByProviderAndProviderUserID returns the identity row matching the given
// provider and provider-specific user ID (e.g. Google's "sub" claim).
// Returns nil, nil when no matching row exists.
func (r *OAuthIdentityRepository) FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*models.OAuthIdentity, error) {
	var identity models.OAuthIdentity
	if err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		First(&identity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &identity, nil
}

// FindByUserIDAndProvider returns the identity link for a local user + provider
// combination. Returns nil, nil when not found.
func (r *OAuthIdentityRepository) FindByUserIDAndProvider(ctx context.Context, userID uint, provider string) (*models.OAuthIdentity, error) {
	var identity models.OAuthIdentity
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider).
		First(&identity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &identity, nil
}
