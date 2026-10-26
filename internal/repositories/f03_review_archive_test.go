package repositories

import (
	"context"
	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"testing"
	"time"
)

func TestReviewF03ArchiveErasureOrder(t *testing.T) {
	for _, erase := range []bool{false, true} {
		name := "before_erasure_control"
		if erase {
			name = "after_erasure"
		}
		t.Run(name, func(t *testing.T) {
			db := testDB(t)
			ctx := tenant.WithTenant(context.Background(), "review-a")
			r := NewAuditRepository(db, WithAuditKeys(durableKeys(t, "k1", "k1")))
			base, err := r.Checkpoint(ctx)
			auditMust(t, err)
			uid := uint(42)
			r.Record(audit.WithActor(ctx, uid), &models.AuditLog{UserID: &uid, Event: "login", Success: true})
			if erase {
				auditMust(t, r.AnonymizeUser(ctx, uid))
			}
			end, err := r.Checkpoint(ctx)
			auditMust(t, err)
			auditMust(t, r.VerifyAgainst(ctx, base, end))
			p := RetentionPolicy{Approval: "SYNTHETIC REVIEW ONLY", Enabled: true, Before: time.Now().Add(time.Hour), MaxRows: 100}
			a, err := r.Archive(ctx, p, base)
			auditMust(t, err)
			if len(a.Events) != 1 {
				t.Fatal("missing event")
			}
			auditMust(t, r.PurgeArchive(ctx, p, a, end))
			if err := r.RestoreArchive(ctx, a, end); err != nil {
				t.Fatalf("valid archive after erasure=%v cannot restore: %v", erase, err)
			}
			auditMust(t, r.VerifyAgainst(ctx, base, end))
		})
	}
}
