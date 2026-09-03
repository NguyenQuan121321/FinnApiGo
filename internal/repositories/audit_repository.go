package repositories

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

const GenesisAuditHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditRepository writes security events. Writes are best-effort and never
// propagate errors to the caller — audit logging must not break requests —
// but failures ARE logged so silent audit gaps are observable.
type AuditRepository struct {
	db      *gorm.DB
	hmacKey []byte
}

func NewAuditRepository(db *gorm.DB, opts ...func(*AuditRepository)) *AuditRepository {
	r := &AuditRepository{
		db:      db,
		hmacKey: []byte("audit-hash-chain-default-secret-32b"),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// WithAuditHMACKey configures custom HMAC secret key for tamper-evident hash chaining (P2.6).
func WithAuditHMACKey(key []byte) func(*AuditRepository) {
	return func(r *AuditRepository) {
		r.hmacKey = key
	}
}

func computeRecordHash(key []byte, prevHash, tenantID, event string, userID uint, email, ip string, success bool, detail string) string {
	h := hmac.New(sha256.New, key)
	payload := fmt.Sprintf("%s|%s|%s|%d|%s|%s|%t|%s", prevHash, tenantID, event, userID, email, ip, success, detail)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// Record writes an audit row. Context is threaded for future async/worker
// migration (§7). Implements tamper-evident hash chaining (P2.6).
func (r *AuditRepository) Record(ctx context.Context, entry *models.AuditLog) {
	if entry.TenantID == "" {
		entry.TenantID = tenant.FromContext(ctx)
	}
	if len(r.hmacKey) > 0 && entry.RecordHash == "" {
		var last models.AuditLog
		prevHash := GenesisAuditHash
		if err := r.db.WithContext(ctx).Where("tenant_id = ?", entry.TenantID).Order("id DESC").First(&last).Error; err == nil && last.RecordHash != "" {
			prevHash = last.RecordHash
		}
		entry.PrevHash = prevHash
		var uid uint
		if entry.UserID != nil {
			uid = *entry.UserID
		}
		entry.RecordHash = computeRecordHash(r.hmacKey, prevHash, entry.TenantID, entry.Event, uid, entry.Email, entry.IPAddress, entry.Success, entry.Detail)
	}

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

// PurgeOlderThan removes audit rows created before the cutoff, in
// LIMIT-batched statements (P1 discipline) — audit retention execution for
// AUDIT_RETENTION_DAYS (R4). Returns the rows removed.
func (r *AuditRepository) PurgeOlderThan(ctx context.Context, before time.Time) (int64, error) {
	return batchedDelete(r.db.WithContext(ctx), &models.AuditLog{}, "created_at < ?", before)
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
	if err := r.db.WithContext(ctx).Model(&models.AuditLog{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var entries []models.AuditLog
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC, id DESC").
		Offset(offset).
		Limit(limit).
		Find(&entries).Error
	return entries, total, err
}

// AnonymizeUser scrubs PII email from audit records belonging to the erased user (P1.3 GDPR).
func (r *AuditRepository) AnonymizeUser(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&models.AuditLog{}).
		Where("user_id = ?", userID).
		Update("email", "anonymized@gdpr.local").Error
}

// FindAllPaginated returns paginated audit events for a tenant (P2.3 admin).
func (r *AuditRepository) FindAllPaginated(ctx context.Context, tenantID string, page, limit int) ([]models.AuditLog, int64, error) {
	if tenantID == "" {
		tenantID = tenant.FromContext(ctx)
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit
	var total int64
	q := r.db.WithContext(ctx).Model(&models.AuditLog{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var entries []models.AuditLog
	err := q.Order("created_at DESC, id DESC").
		Offset(offset).
		Limit(limit).
		Find(&entries).Error
	return entries, total, err
}

// StreamAll returns all audit records for a tenant ordered by time, used for CSV/NDJSON exports (P2.3).
func (r *AuditRepository) StreamAll(ctx context.Context, tenantID string) ([]models.AuditLog, error) {
	if tenantID == "" {
		tenantID = tenant.FromContext(ctx)
	}
	var entries []models.AuditLog
	q := r.db.WithContext(ctx).Model(&models.AuditLog{})
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	err := q.Order("id ASC").Find(&entries).Error
	return entries, err
}

// VerifyChain verifies cryptographic continuity and HMAC integrity of the audit hash chain (P2.6).
func (r *AuditRepository) VerifyChain(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		tenantID = tenant.FromContext(ctx)
	}
	var entries []models.AuditLog
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("id ASC").
		Find(&entries).Error
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return true, nil
	}

	expectedPrev := GenesisAuditHash
	for _, e := range entries {
		if e.PrevHash != expectedPrev {
			return false, fmt.Errorf("hash chain broken at id %d: expected prev_hash %s, got %s", e.ID, expectedPrev, e.PrevHash)
		}
		var uid uint
		if e.UserID != nil {
			uid = *e.UserID
		}
		computed := computeRecordHash(r.hmacKey, e.PrevHash, e.TenantID, e.Event, uid, e.Email, e.IPAddress, e.Success, e.Detail)
		if subtle.ConstantTimeCompare([]byte(computed), []byte(e.RecordHash)) != 1 {
			return false, fmt.Errorf("tampered record at id %d: expected record_hash %s, got %s", e.ID, computed, e.RecordHash)
		}
		expectedPrev = e.RecordHash
	}
	return true, nil
}
