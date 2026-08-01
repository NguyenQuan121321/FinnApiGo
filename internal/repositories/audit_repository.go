package repositories

import (
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

// AuditRepository writes security events. Writes are best-effort and never
// propagate errors to the caller — audit logging must not break requests.
type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Record writes an audit row, swallowing the error intentionally.
func (r *AuditRepository) Record(entry *models.AuditLog) {
	_ = r.db.Create(entry).Error
}
