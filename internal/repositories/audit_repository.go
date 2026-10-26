package repositories

import (
	"context"

	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"gorm.io/gorm"
	"log/slog"
	"time"
)

const GenesisAuditHash = "0000000000000000000000000000000000000000000000000000000000000000"

type AuditRepository struct {
	db         *gorm.DB
	keys       *audit.Keys
	maxPending int
}

func NewAuditRepository(db *gorm.DB, opts ...func(*AuditRepository)) *AuditRepository {
	// In-memory SQLite has a different database per connection. It is a test
	// adapter only; MySQL uses its ordinary replica-safe connection pool.
	if db.Name() == "sqlite" {
		if pool, err := db.DB(); err == nil {
			pool.SetMaxOpenConns(1)
		}
	}
	r := &AuditRepository{db: db, keys: audit.EphemeralKeys(), maxPending: 10000}
	for _, opt := range opts {
		opt(r)
	}
	return r
}
func WithAuditKeys(keys *audit.Keys) func(*AuditRepository) {
	return func(r *AuditRepository) { r.keys = keys }
}
func WithAuditCapacity(n int) func(*AuditRepository) {
	return func(r *AuditRepository) {
		if n > 0 {
			r.maxPending = n
		}
	}
}

// Record preserves the old consumer interface. Operation records latch errors
// into the enclosing SQL transaction; callers needing a result use Admit.
func (r *AuditRepository) Record(ctx context.Context, e *models.AuditLog) {
	err := r.Admit(ctx, e)
	if err != nil {
		if o := database.CurrentOperation(ctx); o != nil {
			o.Fail(audit.ErrUnavailable)
		}
		slog.Error("audit admission failed", "code", "admission_unavailable")
		return
	}
	if database.CurrentOperation(ctx) == nil {
		_, _ = r.Dispatch(ctx, 100)
	}
}
func (r *AuditRepository) BatchInsert(ctx context.Context, entries []*models.AuditLog) int {
	n := 0
	for _, e := range entries {
		if err := r.Admit(ctx, e); err != nil {
			break
		}
		n++
	}
	if database.CurrentOperation(ctx) == nil {
		_, _ = r.Dispatch(ctx, 100)
	}
	return n
}

// An arbitrary date is insufficient authorization to destroy signed history.
func (r *AuditRepository) PurgeOlderThan(context.Context, time.Time) (int64, error) {
	return 0, audit.ErrPolicy
}

// FindByUserIDPaginated returns paginated audit events for a user (P1.4).
func (r *AuditRepository) FindByUserIDPaginated(ctx context.Context, userID uint, page, limit int) ([]models.AuditLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit
	var total int64
	if err := database.FromContext(ctx, r.db).Model(&models.AuditLog{}).Where("user_id = ? AND tenant_id = ?", userID, tenant.FromContext(ctx)).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var entries []models.AuditLog
	err := database.FromContext(ctx, r.db).
		Where("user_id = ? AND tenant_id = ?", userID, tenant.FromContext(ctx)).
		Order("created_at DESC, id DESC").
		Offset(offset).
		Limit(limit).
		Find(&entries).Error
	return entries, total, err
}

// AnonymizeUser scrubs PII email from audit records belonging to the erased user (P1.3 GDPR).
func (r *AuditRepository) AnonymizeUser(ctx context.Context, userID uint) error {
	return database.FromContext(ctx, r.db).Model(&models.AuditLog{}).
		Where("user_id = ? AND tenant_id = ?", userID, tenant.FromContext(ctx)).
		Updates(map[string]any{"email": "anonymized@gdpr.local", "ip_address": "", "detail": ""}).Error
}

// FindAllPaginated returns paginated audit events for a tenant (P2.3 admin).
func (r *AuditRepository) FindAllPaginated(ctx context.Context, tenantID string, page, limit int) ([]models.AuditLog, int64, error) {
	var err error
	tenantID, err = scopeTenant(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit
	var total int64
	q := database.FromContext(ctx, r.db).Model(&models.AuditLog{})
	q = q.Where("tenant_id = ?", tenantID)
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var entries []models.AuditLog
	err = q.Order("created_at DESC, id DESC").
		Offset(offset).
		Limit(limit).
		Find(&entries).Error
	return entries, total, err
}

// StreamAll returns all audit records for a tenant ordered by time, used for CSV/NDJSON exports (P2.3).
func (r *AuditRepository) StreamAll(ctx context.Context, tenantID string) ([]models.AuditLog, error) {
	var err error
	tenantID, err = scopeTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var entries []models.AuditLog
	q := database.FromContext(ctx, r.db).Model(&models.AuditLog{})
	q = q.Where("tenant_id = ?", tenantID)
	err = q.Order("version ASC, sequence ASC, id ASC").Find(&entries).Error
	return entries, err
}
