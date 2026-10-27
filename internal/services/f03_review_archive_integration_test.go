//go:build integration

package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/google/uuid"
)

func TestF03ReviewRealAsyncErasureArchiveOrders(t *testing.T) {
	for _, order := range []string{"archive-before-erasure", "archive-after-erasure", "already-anonymized-v1"} {
		t.Run(order, func(t *testing.T) {
			db, _ := f03DB(t)
			kv := f03Redis(t)
			keys := f03Keys(t)
			r := repositories.NewAuditRepository(db, repositories.WithAuditKeys(keys))
			w := NewAsyncAuditWriter(r, r, config.AuditConfig{BufferSize: 1, FlushBatch: 64})
			t.Cleanup(w.Close)
			svc, _ := f03Auth(t, db, kv, w)
			password := "F03ArchiveSynthetic42!"
			hashed, err := hash.HashPassword(password, hash.MinCost)
			mutationMust(t, err)
			for _, tid := range []string{"a", "b", "default"} {
				t.Run(tid, func(t *testing.T) {
					mutationMust(t, db.Where("id = ?", tid).FirstOrCreate(&models.Tenant{ID: tid, Slug: tid, Name: tid, IsActive: true}).Error)
					ctx := audit.WithCorrelation(tenant.WithTenant(context.Background(), tid), uuid.NewString())
					name := uuid.NewString()
					u := &models.User{TenantID: tid, Username: name, Email: name + "@example.invalid", Password: hashed, IsActive: true, IsEmailVerified: true}
					mutationMust(t, repositories.NewUserRepository(db).Create(ctx, u))
					base, err := r.Checkpoint(ctx)
					mutationMust(t, err)
					pair, _, _, err := svc.Login(ctx, LoginInput{Email: u.Email, Password: password}, "127.0.0.1", "synthetic")
					mutationMust(t, err)
					_, err = svc.Refresh(ctx, pair.RefreshToken, "127.0.0.1", "synthetic")
					mutationMust(t, err)
					f03Drain(t, r)
					end, err := r.Checkpoint(ctx)
					mutationMust(t, err)
					p := repositories.RetentionPolicy{Approval: "SYNTHETIC REPAIR REHEARSAL ONLY", Enabled: true, Before: time.Now().Add(time.Hour), MaxRows: 1000}
					original, err := r.Archive(ctx, p, base)
					mutationMust(t, err)
					if len(original.Events) < 2 {
						t.Fatal("actual async login/refresh evidence missing")
					}
					for _, e := range original.Events {
						if e.ActorID != u.ID || e.ActorKind != "authenticated" || e.UserID == nil || *e.UserID != u.ID {
							t.Fatal("trusted actor/subject missing")
						}
					}
					if order == "already-anonymized-v1" {
						// Reproduce the exact on-disk result from the reviewed release,
						// without changing any signed field or resigning history.
						mutationMust(t, db.Model(&models.AuditLog{}).Where("tenant_id = ? AND user_id = ?", tid, u.ID).Update("email", "anonymized@gdpr.local").Error)
					} else {
						mutationMust(t, r.AnonymizeUser(ctx, u.ID))
					}
					mutationMust(t, r.VerifyAgainst(ctx, base, end))
					a := original
					if order != "archive-before-erasure" {
						a, err = r.Archive(ctx, p, base)
						mutationMust(t, err)
					}
					for i, e := range a.Events {
						if e.Email != "" || e.IPAddress != "" || e.Detail != "" || string(audit.Canonical(&e)) != string(audit.Canonical(&original.Events[i])) || e.RecordHash != original.Events[i].RecordHash {
							t.Fatal("erasure changed signed evidence or retained ancillary PII")
						}
					}
					if a.Base != original.Base || a.End != end {
						t.Fatal("erasure changed trusted checkpoints")
					}
					hold := p
					hold.LegalHold = true
					if _, err := r.Archive(ctx, hold, base); !errors.Is(err, audit.ErrPolicy) {
						t.Fatal("archive ignored legal hold")
					}
					if err := r.PurgeArchive(ctx, hold, a, end); !errors.Is(err, audit.ErrPolicy) {
						t.Fatal("purge ignored legal hold")
					}
					clone := func() repositories.AuditArchive {
						b := a
						b.Events = append([]models.AuditLog(nil), a.Events...)
						return b
					}
					bad := clone()
					bad.Events = bad.Events[:len(bad.Events)-1]
					if r.PurgeArchive(ctx, p, bad, end) == nil {
						t.Fatal("truncated archive authorized purge")
					}
					bad = clone()
					bad.Events[0].Action = "tampered"
					if r.PurgeArchive(ctx, p, bad, end) == nil {
						t.Fatal("tampered archive authorized purge")
					}
					mutationMust(t, r.VerifyAgainst(ctx, base, end))
					mutationMust(t, r.PurgeArchive(ctx, p, a, end))
					assertPurged := func() {
						t.Helper()
						var count int64
						mutationMust(t, db.Model(&models.AuditLog{}).Where("tenant_id = ?", tid).Count(&count).Error)
						var boundary models.AuditBoundary
						mutationMust(t, db.Where("tenant_id = ?", tid).First(&boundary).Error)
						if count != 0 || boundary.Sequence != end.Sequence || boundary.Hash != end.Hash {
							t.Fatal("failed restore left partial rows or moved boundary")
						}
					}
					for _, field := range []string{"email", "ip", "detail", "tamper", "truncation", "checkpoint"} {
						bad = clone()
						switch field {
						case "email":
							bad.Events[1].Email = "private@example.invalid"
						case "ip":
							bad.Events[1].IPAddress = "192.0.2.1"
						case "detail":
							bad.Events[1].Detail = "private"
						case "tamper":
							bad.Events[1].UserID = nil
						case "truncation":
							bad.Events = bad.Events[:len(bad.Events)-1]
						case "checkpoint":
							bad.End.MAC = "invalid"
						}
						if r.RestoreArchive(ctx, bad, end) == nil {
							t.Fatalf("restore accepted %s", field)
						}
						assertPurged()
					}
					key := func(s string) string {
						b := sha256.Sum256([]byte("F03 public synthetic fixture " + s))
						return base64.StdEncoding.EncodeToString(b[:])
					}
					for _, missing := range []string{"wrong", "retired-signing", "retired-checkpoint"} {
						signingID, signingKey, cpID, cpKey := "f03", key("audit"), "checkpoint-v1", key("checkpoint")
						switch missing {
						case "wrong":
							signingKey = key("wrong")
						case "retired-signing":
							signingID, signingKey = "new", key("new")
						case "retired-checkpoint":
							cpID, cpKey = "new-cp", key("new-cp")
						}
						other, err := audit.NewKeyRing(signingID, map[string]string{signingID: signingKey}, cpID, map[string]string{cpID: cpKey})
						mutationMust(t, err)
						if repositories.NewAuditRepository(db, repositories.WithAuditKeys(other)).RestoreArchive(ctx, a, end) == nil {
							t.Fatalf("restore accepted %s keys", missing)
						}
						assertPurged()
					}
					mutationMust(t, db.Exec("CREATE TRIGGER f03_review_restore_fail BEFORE INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.sequence = 2 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic restore failure'; END IF; END").Error)
					if r.RestoreArchive(ctx, a, end) == nil {
						t.Fatal("restore hid MySQL failure")
					}
					assertPurged()
					mutationMust(t, db.Exec("DROP TRIGGER f03_review_restore_fail").Error)
					if order == "already-anonymized-v1" {
						// Also restore an archive produced by the old release itself.
						for i := range a.Events {
							a.Events[i].Email = "anonymized@gdpr.local"
						}
					}
					mutationMust(t, r.RestoreArchive(ctx, a, end))
					mutationMust(t, r.VerifyAgainst(ctx, base, end))
					var restored []models.AuditLog
					mutationMust(t, db.Where("tenant_id = ?", tid).Order("sequence").Find(&restored).Error)
					for i, e := range restored {
						if e.Email != "" || e.RecordHash != original.Events[i].RecordHash || string(audit.Canonical(&e)) != string(audit.Canonical(&original.Events[i])) {
							t.Fatal("restore changed signed history or restored ancillary PII")
						}
					}
					last := restored[len(restored)-1]
					mutationMust(t, db.Delete(&last).Error)
					if r.VerifyAgainst(ctx, base, end) == nil {
						t.Fatal("tail truncation accepted against trusted reference")
					}
					mutationMust(t, db.Create(&last).Error)
					mutationMust(t, r.VerifyAgainst(ctx, base, end))
				})
			}
		})
	}
}
