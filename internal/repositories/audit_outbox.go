package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AuditOperation is the real service transaction boundary. Expected domain
// denials commit lockout/containment plus evidence. Infrastructure errors and
// admission failures roll back every SQL repository write. Redis/network work
// is deliberately outside this atomicity claim.
func (r *AuditRepository) AuditOperation(ctx context.Context, fn func(context.Context) error, denial func(error) bool) error {
	if database.CurrentOperation(ctx) != nil {
		return fn(ctx)
	}
	var result error
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		inner, op := database.BindOperation(ctx, tx)
		result = fn(inner)
		if failure := op.Failure(); failure != nil {
			return audit.ErrUnavailable
		}
		if result != nil && !denial(result) {
			return result
		}
		return nil
	})
	if err != nil {
		if result == nil || errors.Is(err, audit.ErrUnavailable) {
			return audit.ErrUnavailable
		}
		return err
	}
	if !database.AsyncDelivery(ctx) {
		_, _ = r.Dispatch(ctx, 1000)
	}
	return result
}

// Admit signs and stores the immutable event under a per-tenant DB row lock.
// The outbox and business mutation commit together. Head capacity also counts
// dead letters, so poison cannot silently consume unbounded durable storage.
func (r *AuditRepository) Admit(ctx context.Context, in *models.AuditLog) error {
	e, err := audit.Capture(ctx, in)
	if err != nil {
		return audit.ErrUnavailable
	}
	return database.FromContext(ctx, r.db).Transaction(func(tx *gorm.DB) error {
		var old models.AuditOutbox
		err := tx.Where("event_id = ?", e.EventID).First(&old).Error
		if err == nil {
			return audit.ErrUnavailable
		} // caller identity reuse is rejected; delivery replay is idempotent
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return audit.ErrUnavailable
		}
		h := models.AuditHead{TenantID: e.TenantID, Hash: GenesisAuditHash}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&h).Error; err != nil {
			return audit.ErrUnavailable
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ?", e.TenantID).First(&h).Error; err != nil {
			return audit.ErrUnavailable
		}
		if h.Pending >= r.maxPending {
			return audit.ErrUnavailable
		}
		seq := h.Sequence + 1
		e.Sequence = &seq
		e.PrevHash = h.Hash
		r.keys.Sign(e)
		payload, err := json.Marshal(e)
		if err != nil {
			return audit.ErrUnavailable
		}
		o := models.AuditOutbox{EventID: e.EventID, TenantID: e.TenantID, Sequence: seq, Hash: e.RecordHash, KeyID: e.KeyID, Payload: string(payload), State: "pending", AvailableAt: time.Now().UTC(), CreatedAt: e.CreatedAt}
		if err := tx.Create(&o).Error; err != nil {
			return audit.ErrUnavailable
		}
		return tx.Model(&h).Updates(map[string]any{"sequence": seq, "hash": e.RecordHash, "pending": h.Pending + 1}).Error
	})
}

const auditLease = 30 * time.Second
const auditMaxAttempts = 8

// Claim uses SKIP LOCKED on MySQL. A fresh token fences stale workers, even
// after their lease expires and another replica has reclaimed the row.
func (r *AuditRepository) Claim(ctx context.Context, now time.Time) (*models.AuditOutbox, error) {
	now = now.UTC()
	var row models.AuditOutbox
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx.Where("(state = ? AND available_at <= ?) OR (state = ? AND lease_until <= ?)", "pending", now, "leased", now).Order("available_at, event_id")
		if tx.Name() == "mysql" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
		}
		if err := q.First(&row).Error; err != nil {
			return err
		}
		until := now.Add(auditLease)
		row.State = "leased"
		row.LeaseToken = uuid.NewString()
		row.LeaseUntil = &until
		row.Attempts++
		if row.Attempts > auditMaxAttempts {
			row.State = "dead"
			row.LastError = "lease_exhausted"
		}
		return tx.Save(&row).Error
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err == nil && row.State == "dead" {
		return nil, nil
	}
	return &row, err
}

// Deliver locks the claim and inserts/ACKs in one transaction. A duplicate
// insert is accepted only if the persisted canonical event and MAC match.
func (r *AuditRepository) Deliver(ctx context.Context, claim *models.AuditOutbox) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row models.AuditOutbox
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("event_id = ?", claim.EventID).First(&row).Error; err != nil {
			return err
		}
		if row.State == "delivered" {
			return nil
		}
		if row.State != "leased" || row.LeaseToken != claim.LeaseToken || row.LeaseUntil == nil || !row.LeaseUntil.After(time.Now()) {
			return audit.ErrUnavailable
		}
		var e models.AuditLog
		if json.Unmarshal([]byte(row.Payload), &e) != nil || e.EventID != row.EventID || e.TenantID != row.TenantID || e.Sequence == nil || *e.Sequence != row.Sequence || e.RecordHash != row.Hash || e.KeyID != row.KeyID {
			return audit.ErrIntegrity
		}
		if err := r.keys.Verify(&e); err != nil {
			return err
		}
		var prior models.AuditLog
		err := tx.Where("event_id = ?", e.EventID).First(&prior).Error
		switch {
		case err == nil:
			if string(audit.Canonical(&prior)) != string(audit.Canonical(&e)) || prior.RecordHash != e.RecordHash {
				return audit.ErrIntegrity
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := tx.Create(&e).Error; err != nil {
				return err
			}
		default:
			return err
		}
		if err := tx.Model(&models.AuditHead{}).Where("tenant_id = ? AND pending > 0", row.TenantID).Update("pending", gorm.Expr("pending - 1")).Error; err != nil {
			return err
		}
		return tx.Model(&row).Updates(map[string]any{"state": "delivered", "payload": "", "lease_token": "", "lease_until": nil, "last_error": ""}).Error
	})
}

func (r *AuditRepository) FailClaim(ctx context.Context, c *models.AuditOutbox, now time.Time) error {
	now = now.UTC()
	state := "pending"
	if c.Attempts >= auditMaxAttempts {
		state = "dead"
	}
	backoff := time.Second * time.Duration(1<<min(c.Attempts, 8))
	return r.db.WithContext(ctx).Model(&models.AuditOutbox{}).Where("event_id = ? AND state = ? AND lease_token = ?", c.EventID, "leased", c.LeaseToken).Updates(map[string]any{"state": state, "available_at": now.Add(backoff), "lease_until": nil, "lease_token": "", "last_error": "delivery_failed"}).Error
}

// RequeueDead is tenant-scoped operator recovery after repairing the cause.
// No public route grants this authority. Resetting attempts is explicit.
func (r *AuditRepository) RequeueDead(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Model(&models.AuditOutbox{}).Where("tenant_id = ? AND event_id = ? AND state = ?", tenant.FromContext(ctx), id, "dead").Updates(map[string]any{"state": "pending", "attempts": 0, "available_at": time.Now().UTC(), "last_error": ""})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *AuditRepository) Dispatch(ctx context.Context, limit int) (int, error) {
	limit = min(max(limit, 1), 1000)
	n := 0
	for range limit {
		c, err := r.Claim(ctx, time.Now().UTC())
		if err != nil {
			return n, err
		}
		if c == nil {
			break
		}
		if err := r.Deliver(ctx, c); err != nil {
			if failure := r.FailClaim(ctx, c, time.Now().UTC()); failure != nil {
				return n, failure
			}
			return n, err
		}
		n++
	}
	return n, nil
}

type AuditBacklog struct {
	Pending int64
	Dead    int64
	Oldest  *time.Time
}

func (r *AuditRepository) Backlog(ctx context.Context) (AuditBacklog, error) {
	var b AuditBacklog
	q := r.db.WithContext(ctx).Model(&models.AuditOutbox{})
	if err := q.Session(&gorm.Session{}).Where("state IN ?", []string{"pending", "leased"}).Count(&b.Pending).Error; err != nil {
		return b, err
	}
	if err := q.Session(&gorm.Session{}).Where("state = ?", "dead").Count(&b.Dead).Error; err != nil {
		return b, err
	}
	var oldest models.AuditOutbox
	err := q.Session(&gorm.Session{}).Where("state <> ?", "delivered").Order("created_at").First(&oldest).Error
	if err == nil {
		b.Oldest = &oldest.CreatedAt
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return b, err
	}
	return b, nil
}

func (r *AuditRepository) OutboxStats(ctx context.Context) (int64, int64, time.Duration, error) {
	b, err := r.Backlog(ctx)
	var age time.Duration
	if b.Oldest != nil {
		age = time.Since(*b.Oldest)
	}
	return b.Pending, b.Dead, age, err
}

// ValidateKeyHistory prevents retiring a verification key while hot rows or
// undelivered events need it. Independently archived keys remain an operator
// obligation and are checked again on archive restore.
func (r *AuditRepository) ValidateKeyHistory(ctx context.Context) error {
	for _, model := range []any{&models.AuditLog{}, &models.AuditOutbox{}} {
		var ids []string
		q := r.db.WithContext(ctx).Model(model).Distinct("key_id").Limit(9)
		if _, ok := model.(*models.AuditLog); ok {
			q = q.Where("version = 1")
		} else {
			q = q.Where("state <> ?", "delivered")
		}
		if err := q.Pluck("key_id", &ids).Error; err != nil {
			return audit.ErrUnavailable
		}
		for _, id := range ids {
			if !r.keys.HasKey(id) {
				return audit.ErrUnavailable
			}
		}
	}
	return nil
}
