package repositories

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// WebhookRepository persists webhook endpoints and outbox deliveries (P2.5).
type WebhookRepository struct {
	db *gorm.DB
}

func NewWebhookRepository(db *gorm.DB) *WebhookRepository {
	return &WebhookRepository{db: db}
}

func (r *WebhookRepository) CreateEndpoint(ctx context.Context, ep *models.WebhookEndpoint) error {
	if ep.TenantID == "" {
		ep.TenantID = tenant.FromContext(ctx)
	}
	return r.db.WithContext(ctx).Create(ep).Error
}

func (r *WebhookRepository) FindActiveEndpointsByEvent(ctx context.Context, tenantID, event string) ([]models.WebhookEndpoint, error) {
	if tenantID == "" {
		tenantID = tenant.FromContext(ctx)
	}
	var endpoints []models.WebhookEndpoint
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND is_active = ?", tenantID, true).
		Find(&endpoints).Error
	if err != nil {
		return nil, err
	}

	var matched []models.WebhookEndpoint
	for _, ep := range endpoints {
		events := strings.Split(ep.Events, ",")
		for _, ev := range events {
			if strings.TrimSpace(ev) == "*" || strings.TrimSpace(ev) == event {
				matched = append(matched, ep)
				break
			}
		}
	}
	return matched, nil
}

func (r *WebhookRepository) CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error {
	return r.db.WithContext(ctx).Create(d).Error
}

func (r *WebhookRepository) GetPendingDeliveries(ctx context.Context, limit int) ([]models.WebhookDelivery, error) {
	var deliveries []models.WebhookDelivery
	now := time.Now()
	err := r.db.WithContext(ctx).
		Where("status = ? AND (next_retry_at IS NULL OR next_retry_at <= ?)", "pending", now).
		Order("created_at ASC").
		Limit(limit).
		Find(&deliveries).Error
	return deliveries, err
}

func (r *WebhookRepository) UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry *time.Time, respStatus *int, errMsg string) error {
	updates := map[string]any{
		"status":          status,
		"attempts":        attempts,
		"next_retry_at":   nextRetry,
		"response_status": respStatus,
		"error_msg":       errMsg,
		"updated_at":      time.Now(),
	}
	return r.db.WithContext(ctx).Model(&models.WebhookDelivery{}).
		Where("id = ?", id).
		Updates(updates).Error
}
