package audit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"strings"
	"testing"
	"time"
)

func testKey(label string) string {
	b := sha256.Sum256([]byte(label))
	return base64.StdEncoding.EncodeToString(b[:])
}
func TestCanonicalGoldenAndKeyLifecycle(t *testing.T) {
	k, err := NewKeys("k1", map[string]string{"k1": testKey("one"), "k0": testKey("old")}, testKey("checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	seq := uint64(7)
	uid := uint(42)
	e := &models.AuditLog{Version: 1, EventID: "00000000-0000-4000-8000-000000000001", TenantID: "a", Sequence: &seq, PrevHash: "prior", KeyID: "k1", CreatedAt: time.UnixMilli(1000), ActorKind: "authenticated", ActorID: 42, UserID: &uid, RequestID: "00000000-0000-4000-8000-000000000002", Event: "login", Success: true}
	want := `["finn.audit.event.v1",1,"00000000-0000-4000-8000-000000000001","a",7,"prior","k1",1000,"authenticated",42,42,"00000000-0000-4000-8000-000000000002","login","",true]`
	if string(Canonical(e)) != want {
		t.Fatalf("canonical schema drift: %s", Canonical(e))
	}
	k.Sign(e)
	if err := k.Verify(e); err != nil {
		t.Fatal(err)
	}
	expected := "04d9b9ef230f9243036c20fd16f832e3269af61576200d7542920aa721ca751e"
	if e.RecordHash != expected {
		t.Fatalf("MAC drift: %s", e.RecordHash)
	}
	// Every integrity-relevant projection is covered. Ancillary PII is excluded.
	for _, mutate := range []func(*models.AuditLog){func(e *models.AuditLog) { e.Event = "other" }, func(e *models.AuditLog) { e.TenantID = "b" }, func(e *models.AuditLog) { e.ActorID++ }, func(e *models.AuditLog) { e.RequestID = "other" }, func(e *models.AuditLog) { e.CreatedAt = e.CreatedAt.Add(time.Millisecond) }, func(e *models.AuditLog) { e.Success = false }, func(e *models.AuditLog) { e.Action = "erase" }, func(e *models.AuditLog) { e.ActorKind = "system" }, func(e *models.AuditLog) { e.EventID = "other" }, func(e *models.AuditLog) { e.Version = 0 }, func(e *models.AuditLog) { e.KeyID = "unknown" }, func(e *models.AuditLog) { e.Sequence = nil }} {
		copy := *e
		mutate(&copy)
		if k.Verify(&copy) == nil {
			t.Fatal("tamper accepted")
		}
	}
	rotated, err := NewKeys("k2", map[string]string{"k1": testKey("one"), "k2": testKey("two")}, testKey("checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Verify(e) != nil {
		t.Fatal("rotation lost old verification")
	}
	rotated.Sign(e)
	if e.KeyID != "k2" || rotated.Verify(e) != nil {
		t.Fatal("current key not used")
	}
	retired, _ := NewKeys("k1", map[string]string{"k1": testKey("one")}, testKey("checkpoint"))
	if retired.Verify(e) == nil {
		t.Fatal("unknown retired key accepted")
	}
	c := k.Checkpoint("a", 7, "hash")
	if k.VerifyCheckpoint(c) != nil {
		t.Fatal("checkpoint")
	}
	c.Sequence++
	if k.VerifyCheckpoint(c) == nil {
		t.Fatal("forged checkpoint")
	}
	if k.VerifyCheckpoint(rotated.Checkpoint("a", 7, "hash")) != nil {
		t.Fatal("stable checkpoint domain")
	}
	oldCheckpoint := k.Checkpoint("a", 7, "hash")
	cpRotated, err := NewKeyRing("k1", map[string]string{"k1": testKey("one")}, "cp2", map[string]string{"checkpoint-v1": testKey("checkpoint"), "cp2": testKey("checkpoint-two")})
	if err != nil || cpRotated.VerifyCheckpoint(oldCheckpoint) != nil || cpRotated.Checkpoint("a", 7, "hash").KeyID != "cp2" {
		t.Fatal("checkpoint rotation lost trusted reference", err)
	}
	cpRetired, err := NewKeyRing("k1", map[string]string{"k1": testKey("one")}, "cp2", map[string]string{"cp2": testKey("checkpoint-two")})
	if err != nil || cpRetired.VerifyCheckpoint(oldCheckpoint) == nil {
		t.Fatal("retired checkpoint key accepted", err)
	}
}

func TestKeysRejectInvalidAndCaptureTrust(t *testing.T) {
	for _, value := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("short")), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), base64.StdEncoding.EncodeToString([]byte("audit-hash-chain-default-secret-32b"))} {
		if _, err := NewKeys("k", map[string]string{"k": value}, testKey("cp")); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if _, err := NewKeys("missing", map[string]string{"k": testKey("k")}, testKey("cp")); err == nil {
		t.Fatal("missing current")
	}
	if _, err := NewKeys("k", map[string]string{"k": testKey("same")}, testKey("same")); err == nil {
		t.Fatal("shared domains")
	}
	if _, err := NewKeys("k", map[string]string{"k": testKey("k")}, "bad"); err == nil {
		t.Fatal("invalid checkpoint key")
	}
	ctx := WithCorrelation(tenant.WithTenant(context.Background(), "a"), "00000000-0000-4000-8000-000000000002")
	uid := uint(42)
	input := &models.AuditLog{UserID: &uid, Event: "login", Email: "canary@example.invalid", IPAddress: "127.0.0.1", Detail: "secret canary", Success: true}
	e, err := Capture(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	uid = 99
	if e.ActorKind != "unauthenticated" || *e.UserID != 42 || e.Detail != "" || e.Email != "" || e.IPAddress != "" || e.CreatedAt.IsZero() || e.EventID == "" {
		t.Fatal("untrusted actor/PII/mutable context")
	}
	e, err = Capture(WithActor(ctx, 42), input)
	if err != nil || e.ActorKind != "authenticated" || e.ActorID != 42 {
		t.Fatal("trusted actor lost")
	}
	e, err = Capture(WithSystem(context.Background()), input)
	if err != nil || e.ActorKind != "system" || e.TenantID != "default" {
		t.Fatal("system/default lost")
	}
	for _, in := range []*models.AuditLog{nil, {}, {TenantID: "b", Event: "login"}, {Event: "login", EventID: "bad"}, {Event: strings.Repeat("a", 41)}} {
		if _, err := Capture(ctx, in); err == nil {
			t.Fatal("invalid capture")
		}
	}
}
