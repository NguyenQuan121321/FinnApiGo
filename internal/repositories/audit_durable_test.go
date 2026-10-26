package repositories

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"testing"
	"time"
)

func durableKeys(t *testing.T, current string, ids ...string) *audit.Keys {
	t.Helper()
	keys := map[string]string{}
	for _, id := range ids {
		b := sha256.Sum256([]byte("F03 synthetic " + id))
		keys[id] = base64.StdEncoding.EncodeToString(b[:])
	}
	cp := sha256.Sum256([]byte("F03 independent synthetic checkpoint"))
	k, err := audit.NewKeys(current, keys, base64.StdEncoding.EncodeToString(cp[:]))
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func auditMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func TestDurableAuditClaimsFaultsAndCapacity(t *testing.T) {
	db := testDB(t)
	ctx := tenant.WithTenant(context.Background(), "a")
	k := durableKeys(t, "k1", "k1")
	r := NewAuditRepository(db, WithAuditKeys(k), WithAuditCapacity(1))
	auditMust(t, r.Admit(ctx, &models.AuditLog{Event: "login", Success: true}))
	if r.Admit(ctx, &models.AuditLog{Event: "login"}) == nil {
		t.Fatal("capacity bypass")
	}
	b, err := r.Backlog(ctx)
	auditMust(t, err)
	if b.Pending != 1 || b.Dead != 0 || b.Oldest == nil {
		t.Fatal("backlog signal", b)
	}
	c, err := r.Claim(ctx, time.Now())
	auditMust(t, err)
	if c == nil {
		t.Fatal("claim missing")
	}
	// Expired worker is fenced after a reclaim; a new repository models restart.
	auditMust(t, db.Model(c).Update("lease_until", time.Now().UTC().Add(-time.Minute)).Error)
	next := NewAuditRepository(db, WithAuditKeys(k))
	fresh, err := next.Claim(ctx, time.Now())
	auditMust(t, err)
	if fresh == nil || fresh.LeaseToken == c.LeaseToken || r.Deliver(ctx, c) == nil {
		t.Fatal("stale worker accepted")
	}
	auditMust(t, next.Deliver(ctx, fresh))
	auditMust(t, next.Deliver(ctx, c)) // duplicate ACK
	rows, err := next.StreamAll(ctx, "a")
	auditMust(t, err)
	if len(rows) != 1 {
		t.Fatal("duplicate event")
	}
	auditMust(t, next.Admit(ctx, &models.AuditLog{Event: "refresh_token"}))
	c, err = next.Claim(ctx, time.Now())
	auditMust(t, err)
	auditMust(t, db.Model(c).Update("payload", "corrupt").Error)
	if next.Deliver(ctx, c) == nil {
		t.Fatal("corrupt payload delivered")
	}
	c.Attempts = 8
	auditMust(t, next.FailClaim(ctx, c, time.Now()))
	b, err = next.Backlog(ctx)
	auditMust(t, err)
	if b.Dead != 1 {
		t.Fatal("poison not visible")
	}
	other := tenant.WithTenant(context.Background(), "b")
	if next.RequeueDead(other, c.EventID) == nil {
		t.Fatal("cross tenant recovery")
	}
	auditMust(t, next.RequeueDead(ctx, c.EventID))
	pending, dead, _, err := next.OutboxStats(ctx)
	auditMust(t, err)
	if pending != 1 || dead != 0 {
		t.Fatal("recovery counts")
	}
	n, err := next.Dispatch(ctx, 1)
	if err == nil || n != 0 {
		t.Fatal("poison retry hidden")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if next.Admit(cancelCtx, &models.AuditLog{Event: "login"}) == nil {
		t.Fatal("canceled admission")
	}
	if next.Admit(ctx, &models.AuditLog{TenantID: "b", Event: "login"}) == nil {
		t.Fatal("foreign tenant admission")
	}
	if _, _, err := next.FindAllPaginated(ctx, "b", 1, 10); err == nil {
		t.Fatal("foreign query")
	}
	if _, err := next.StreamAll(ctx, "b"); err == nil {
		t.Fatal("foreign export")
	}
	if ok, err := next.VerifyChain(ctx, "b"); ok || err == nil {
		t.Fatal("foreign verification")
	}
}

func TestAuditOperationRollsBackAndDenialsPersist(t *testing.T) {
	db := testDB(t)
	r := NewAuditRepository(db)
	ctx := context.Background()
	users := NewUserRepository(db)
	err := r.AuditOperation(ctx, func(inner context.Context) error {
		auditMust(t, users.Create(inner, &models.User{Username: "rollback", Email: "rollback@example.invalid"}))
		r.Record(inner, &models.AuditLog{TenantID: "foreign", Event: "login"})
		return nil
	}, func(error) bool { return false })
	if !errors.Is(err, audit.ErrUnavailable) {
		t.Fatal("admission error lost", err)
	}
	var n int64
	auditMust(t, db.Model(&models.User{}).Where("username = ?", "rollback").Count(&n).Error)
	if n != 0 {
		t.Fatal("business mutation escaped rollback")
	}
	denial := errors.New("expected denial")
	err = r.AuditOperation(ctx, func(inner context.Context) error {
		return r.AuditOperation(inner, func(inner context.Context) error {
			r.Record(inner, &models.AuditLog{Event: "login_failed"})
			return denial
		}, func(error) bool { return true })
	}, func(e error) bool { return errors.Is(e, denial) })
	if !errors.Is(err, denial) {
		t.Fatal(err)
	}
	rows, err := r.StreamAll(ctx, "default")
	auditMust(t, err)
	if len(rows) != 1 {
		t.Fatal("denial evidence lost")
	}
	for _, withSuccess := range []bool{false, true} {
		err = r.AuditOperation(ctx, func(inner context.Context) error {
			auditMust(t, users.Create(inner, &models.User{Username: "denied", Email: "denied@example.invalid"}))
			if withSuccess {
				r.Record(inner, &models.AuditLog{Event: "factor_validated", Success: true})
			}
			return denial
		}, func(e error) bool { return errors.Is(e, denial) })
		if !errors.Is(err, denial) {
			t.Fatal(err)
		}
		auditMust(t, db.Model(&models.User{}).Where("username = ?", "denied").Count(&n).Error)
		if n != 0 {
			t.Fatal("denied issuance left partially prepared SQL state")
		}
	}
	err = r.AuditOperation(ctx, func(inner context.Context) error {
		r.Record(inner, &models.AuditLog{Event: "login"})
		return errors.New("infrastructure error")
	}, func(error) bool { return false })
	if err == nil {
		t.Fatal("operation error lost")
	}
	opCtx, op := database.BindOperation(ctx, db)
	if database.CurrentOperation(opCtx) != op {
		t.Fatal("operation binding")
	}
}

func TestAuditArchiveTrustedBoundariesAndErasure(t *testing.T) {
	db := testDB(t)
	ctx := tenant.WithTenant(context.Background(), "a")
	r := NewAuditRepository(db, WithAuditKeys(durableKeys(t, "k1", "k1")))
	base, err := r.Checkpoint(ctx)
	auditMust(t, err)
	uid := uint(42)
	for range 3 {
		r.Record(audit.WithActor(ctx, 42), &models.AuditLog{UserID: &uid, Event: "login", Email: "PII-canary", IPAddress: "secret", Detail: "raw token canary", Success: true})
	}
	end, err := r.Checkpoint(ctx)
	auditMust(t, err)
	auditMust(t, r.VerifyAgainst(ctx, base, end))
	p := RetentionPolicy{Approval: "SYNTHETIC TEST POLICY ONLY", Enabled: true, Before: time.Now().Add(time.Hour), MaxRows: 100}
	a, err := r.Archive(ctx, p, base)
	auditMust(t, err)
	if len(a.Events) != 3 {
		t.Fatal("archive count")
	}
	auditMust(t, r.AnonymizeUser(ctx, uid))
	auditMust(t, r.VerifyAgainst(ctx, base, end))
	// Tamper/reorder/delete/tail truncation against independent references.
	swapped := append([]models.AuditLog(nil), a.Events...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if r.verifyEvents("a", base, end, swapped) == nil {
		t.Fatal("reorder accepted")
	}
	for _, rows := range [][]models.AuditLog{a.Events[:2], a.Events[1:], {a.Events[0], a.Events[2]}} {
		if r.verifyEvents("a", base, end, rows) == nil {
			t.Fatal("delete/truncation accepted")
		}
	}
	original := a.Events[0]
	auditMust(t, db.Model(&models.AuditLog{}).Where("id = ?", original.ID).Update("event", "tampered").Error)
	if r.VerifyAgainst(ctx, base, end) == nil {
		t.Fatal("tamper accepted")
	}
	auditMust(t, db.Model(&models.AuditLog{}).Where("id = ?", original.ID).Update("event", original.Event).Error)
	held := p
	held.LegalHold = true
	if _, err := r.Archive(ctx, held, base); err == nil {
		t.Fatal("legal hold bypass")
	}
	if r.PurgeArchive(ctx, held, a, end) == nil {
		t.Fatal("purge on hold")
	}
	wrong := end
	wrong.Hash = "forged"
	if r.PurgeArchive(ctx, p, a, wrong) == nil {
		t.Fatal("untrusted boundary")
	}
	auditMust(t, r.PurgeArchive(ctx, p, a, end))
	if ok, err := r.VerifyChain(ctx, "a"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if r.VerifyAgainst(ctx, base, end) == nil {
		t.Fatal("external full history verification overlooked deleted archive")
	}
	auditMust(t, r.RestoreArchive(ctx, a, end))
	auditMust(t, r.VerifyAgainst(ctx, base, end))
	if r.RestoreArchive(ctx, a, end) == nil {
		t.Fatal("duplicate restore accepted")
	}
	legacy := &models.AuditLog{TenantID: "a", Event: "old", Email: "legacy"}
	auditMust(t, db.Create(legacy).Error)
	if ok, err := r.VerifyChain(ctx, "a"); ok || !errors.Is(err, audit.ErrLegacy) {
		t.Fatal("legacy promoted", ok, err)
	}
	auditMust(t, r.AnonymizeUser(ctx, uid))
	if _, err := r.Archive(ctx, RetentionPolicy{}, base); err == nil {
		t.Fatal("missing policy")
	}
	// Missing retired key makes restore/verification fail rather than resigning.
	retired := NewAuditRepository(db, WithAuditKeys(durableKeys(t, "k2", "k2")))
	if retired.VerifyAgainst(ctx, base, end) == nil {
		t.Fatal("retired key fabricated verification")
	}
	if retired.ValidateKeyHistory(ctx) == nil {
		t.Fatal("startup accepted removal of key needed by hot history")
	}
	auditMust(t, r.ValidateKeyHistory(ctx))
	if retired.RestoreArchive(ctx, a, end) == nil {
		t.Fatal("restore without key")
	}
}
