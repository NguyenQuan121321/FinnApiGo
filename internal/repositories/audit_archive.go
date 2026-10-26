package repositories

import (
	"context"
	"errors"
	"time"

	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RetentionPolicy is injected by an authorized operator, never inferred from a
// duration environment variable. Production approvals/holds/backup expiry are
// unresolved; the server has no purge route or scheduled v1 purge.
type RetentionPolicy struct {
	Approval  string
	Enabled   bool
	LegalHold bool
	Before    time.Time
	MaxRows   int
}
type AuditArchive struct {
	Base   audit.Checkpoint
	End    audit.Checkpoint
	Events []models.AuditLog
}

const legacyAuditErasureMarker = "anonymized@gdpr.local"

// Older erasure wrote this nonpersonal marker into unsigned v1 Email. Accept
// only that exact compatibility value, normalize a copy, and retain the PII
// guard. Signed identifiers, canonical bytes and trusted references never change.
func normalizeArchivedAncillary(e models.AuditLog) (models.AuditLog, error) {
	if e.Version == 1 && e.Email == legacyAuditErasureMarker {
		e.Email = ""
	}
	if e.Email != "" || e.IPAddress != "" || e.Detail != "" {
		return models.AuditLog{}, audit.ErrIntegrity
	}
	return e, nil
}

func (r *AuditRepository) Checkpoint(ctx context.Context) (audit.Checkpoint, error) {
	var h models.AuditHead
	err := r.db.WithContext(ctx).Where("tenant_id = ?", tenant.FromContext(ctx)).First(&h).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.keys.Checkpoint(tenant.FromContext(ctx), 0, GenesisAuditHash), nil
	}
	if err != nil {
		return audit.Checkpoint{}, err
	}
	return r.keys.Checkpoint(h.TenantID, h.Sequence, h.Hash), nil
}

func (r *AuditRepository) verifyEvents(tid string, base, end audit.Checkpoint, rows []models.AuditLog) error {
	if base.Tenant != tid || end.Tenant != tid || base.Sequence > end.Sequence {
		return audit.ErrIntegrity
	}
	if r.keys.VerifyCheckpoint(base) != nil || r.keys.VerifyCheckpoint(end) != nil {
		return audit.ErrIntegrity
	}
	seq, hash := base.Sequence, base.Hash
	for i := range rows {
		e := &rows[i]
		seq++
		if e.TenantID != tid || e.Sequence == nil || *e.Sequence != seq || e.PrevHash != hash || r.keys.Verify(e) != nil {
			return audit.ErrIntegrity
		}
		hash = e.RecordHash
	}
	if seq != end.Sequence || hash != end.Hash {
		return audit.ErrIntegrity
	}
	return nil
}

// VerifyAgainst uses independently retained references. A stale end checkpoint
// only protects its own prefix, not a newer tail or events never admitted.
func (r *AuditRepository) VerifyAgainst(ctx context.Context, base, end audit.Checkpoint) error {
	tid := tenant.FromContext(ctx)
	var rows []models.AuditLog
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND version = 1 AND sequence > ? AND sequence <= ?", tid, base.Sequence, end.Sequence).Order("sequence").Find(&rows).Error; err != nil {
		return err
	}
	return r.verifyEvents(tid, base, end, rows)
}

// VerifyChain checks local continuity; it does NOT claim external tail proof.
// Legacy rows fail explicitly rather than being relabeled or resigned.
func (r *AuditRepository) VerifyChain(ctx context.Context, tid string) (bool, error) {
	if _, err := scopeTenant(ctx, tid); err != nil {
		return false, err
	}
	tid = tenant.FromContext(ctx)
	var n int64
	if err := r.db.WithContext(ctx).Model(&models.AuditLog{}).Where("tenant_id = ? AND version <> 1", tid).Count(&n).Error; err != nil {
		return false, err
	}
	if n > 0 {
		return false, audit.ErrLegacy
	}
	base := r.keys.Checkpoint(tid, 0, GenesisAuditHash)
	var b models.AuditBoundary
	err := r.db.WithContext(ctx).Where("tenant_id = ?", tid).First(&b).Error
	if err == nil {
		base = r.keys.Checkpoint(tid, b.Sequence, b.Hash)
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return false, err
	}
	end, err := r.Checkpoint(ctx)
	if err != nil {
		return false, err
	}
	err = r.VerifyAgainst(ctx, base, end)
	return err == nil, err
}

// Archive exports a bounded prefix. The caller must durably retain the archive
// and its end checkpoint independently BEFORE authorizing PurgeArchive.
func (r *AuditRepository) Archive(ctx context.Context, p RetentionPolicy, base audit.Checkpoint) (AuditArchive, error) {
	var a AuditArchive
	if !p.Enabled || p.LegalHold || p.Approval == "" || p.MaxRows < 1 || p.MaxRows > 1000 || p.Before.IsZero() {
		return a, audit.ErrPolicy
	}
	tid := tenant.FromContext(ctx)
	a.Base = base
	if base.Tenant != tid || r.keys.VerifyCheckpoint(base) != nil {
		return a, audit.ErrIntegrity
	}
	// Fetch in sequence order first; a timestamp cutoff must not skip a gap.
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND version = 1 AND sequence > ?", tid, base.Sequence).Order("sequence").Limit(p.MaxRows).Find(&a.Events).Error; err != nil {
		return a, err
	}
	for i, e := range a.Events {
		if !e.CreatedAt.Before(p.Before) {
			a.Events = a.Events[:i]
			break
		}
		var err error
		a.Events[i], err = normalizeArchivedAncillary(e)
		if err != nil {
			return AuditArchive{}, err
		}
	}
	a.End = base
	if len(a.Events) > 0 {
		e := a.Events[len(a.Events)-1]
		a.End = r.keys.Checkpoint(tid, *e.Sequence, e.RecordHash)
	}
	if err := r.verifyEvents(tid, a.Base, a.End, a.Events); err != nil {
		return AuditArchive{}, err
	}
	return a, nil
}

// PurgeArchive requires the separately retained end reference and rechecks all
// rows within the deletion transaction. Receipts/heads remain for deduplication.
func (r *AuditRepository) PurgeArchive(ctx context.Context, p RetentionPolicy, a AuditArchive, trusted audit.Checkpoint) error {
	if !p.Enabled || p.LegalHold || p.Approval == "" || p.MaxRows < 1 || len(a.Events) > p.MaxRows || trusted != a.End || p.Before.IsZero() {
		return audit.ErrPolicy
	}
	tid := tenant.FromContext(ctx)
	if err := r.verifyEvents(tid, a.Base, a.End, a.Events); err != nil {
		return err
	}
	for _, e := range a.Events {
		if !e.CreatedAt.Before(p.Before) {
			return audit.ErrPolicy
		}
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var head models.AuditHead
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ?", tid).First(&head).Error; err != nil {
			return err
		}
		var b models.AuditBoundary
		err := tx.Where("tenant_id = ?", tid).First(&b).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			b = models.AuditBoundary{TenantID: tid, Hash: GenesisAuditHash}
		} else if err != nil {
			return err
		}
		if b.Sequence != a.Base.Sequence || b.Hash != a.Base.Hash {
			return audit.ErrIntegrity
		}
		var rows []models.AuditLog
		if err := tx.Where("tenant_id = ? AND version = 1 AND sequence > ? AND sequence <= ?", tid, a.Base.Sequence, a.End.Sequence).Order("sequence").Find(&rows).Error; err != nil {
			return err
		}
		if err := r.verifyEvents(tid, a.Base, a.End, rows); err != nil {
			return err
		}
		if err := tx.Where("tenant_id = ? AND version = 1 AND sequence > ? AND sequence <= ?", tid, a.Base.Sequence, a.End.Sequence).Delete(&models.AuditLog{}).Error; err != nil {
			return err
		}
		b.Sequence = a.End.Sequence
		b.Hash = a.End.Hash
		return tx.Save(&b).Error
	})
}

// RestoreArchive restores only the exact archived prefix at the current local
// boundary. It never lowers the admitted head, overwrites newer evidence or
// recreates ancillary PII. Missing retired signing/checkpoint keys fail closed.
func (r *AuditRepository) RestoreArchive(ctx context.Context, a AuditArchive, trusted audit.Checkpoint) error {
	tid := tenant.FromContext(ctx)
	if trusted != a.End || len(a.Events) > 1000 {
		return audit.ErrIntegrity
	}
	if err := r.verifyEvents(tid, a.Base, a.End, a.Events); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var h models.AuditHead
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ?", tid).First(&h).Error; err != nil {
			return err
		}
		var b models.AuditBoundary
		if err := tx.Where("tenant_id = ?", tid).First(&b).Error; err != nil {
			return err
		}
		if b.Sequence != a.End.Sequence || b.Hash != a.End.Hash || h.Sequence < a.End.Sequence {
			return audit.ErrIntegrity
		}
		for _, e := range a.Events {
			e.ID = 0
			normalized, err := normalizeArchivedAncillary(e)
			if err != nil {
				return err
			}
			if err := tx.Create(&normalized).Error; err != nil {
				return err
			}
		}
		return tx.Model(&b).Updates(map[string]any{"sequence": a.Base.Sequence, "hash": a.Base.Hash}).Error
	})
}
