package repositories

import (
	"context"
	"log/slog"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

// AuditRepository writes security events. Writes are best-effort and never
// propagate errors to the caller — audit logging must not break requests —
// but failures ARE logged so silent audit gaps are observable.
type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Record writes an audit row. Context is threaded for future async/worker
// migration (§7).
func (r *AuditRepository) Record(ctx context.Context, entry *models.AuditLog) {
	if err := r.db.WithContext(ctx).Create(entry).Error; err != nil {
		slog.Error("audit write failed",
			"event", entry.Event,
			"user_id", entry.UserID,
			"err", err,
		)
	}
}

// BatchInsert writes multiple audit rows in one round-trip. Used by the
// async audit worker (§7). Returns the count actually inserted (0 on error).
func (r *AuditRepository) BatchInsert(ctx context.Context, entries []*models.AuditLog) int {
	if len(entries) == 0 {
		return 0
	}
	if err := r.db.WithContext(ctx).CreateInBatches(entries, 100).Error; err != nil {
		slog.Error("audit batch insert failed",
			"batch_size", len(entries),
			"event", entries[0].Event,
			"err", err,
		)
		return 0
	}
	return len(entries)
}
