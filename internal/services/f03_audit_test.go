package services_test

import (
	"context"
	"errors"
	"github.com/finnapigo/finnapigo/internal/audit"
	"testing"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestF03ProductionAsyncIntegrity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&models.AuditLog{}, &models.AuditHead{}, &models.AuditOutbox{}, &models.AuditBoundary{}); err != nil {
		t.Fatal(err)
	}
	repo := repositories.NewAuditRepository(db)
	w := services.NewAsyncAuditWriter(repo, repo, config.AuditConfig{BufferSize: 32, FlushBatch: 32})
	for _, tid := range []string{"tenant-a", "tenant-b", "default"} {
		ctx := tenant.WithTenant(context.Background(), tid)
		uid := uint(42)
		w.Record(ctx, &models.AuditLog{UserID: &uid, Event: models.AuditEventLogin, Success: true})
	}
	w.Close()
	for _, tid := range []string{"tenant-a", "tenant-b", "default"} {
		ctx := tenant.WithTenant(context.Background(), tid)
		rows, e := repo.StreamAll(ctx, tid)
		if e != nil || len(rows) != 1 {
			t.Fatalf("tenant=%s rows=%d err=%v", tid, len(rows), e)
		}
		if rows[0].RecordHash == "" {
			t.Fatalf("production async tenant=%s event persisted unsigned", tid)
		}
		if ok, e := repo.VerifyChain(ctx, tid); !ok || e != nil {
			t.Fatalf("tenant=%s integrity=%v err=%v", tid, ok, e)
		}
	}
}

func TestF03DurableShutdownCapacityAndCancellation(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.AuditLog{}, &models.AuditHead{}, &models.AuditOutbox{}, &models.AuditBoundary{}); err != nil {
		t.Fatal(err)
	}
	repo := repositories.NewAuditRepository(db, repositories.WithAuditCapacity(2))
	w := services.NewAsyncAuditWriter(repo, repo, config.AuditConfig{BufferSize: 1, FlushBatch: 10})
	w.Close()
	w.Close() // late handlers still durably admit; no live RAM worker
	ctx, cancel := context.WithCancel(audit.WithActor(tenant.WithTenant(context.Background(), "late"), 42))
	uid := uint(42)
	dropped := services.AuditDroppedEntries.Load()
	for range 2 {
		err := w.AuditOperation(ctx, func(inner context.Context) error {
			w.Record(inner, &models.AuditLog{Event: "late_handler", UserID: &uid, Detail: "F03-password-canary", Success: true})
			return nil
		}, func(error) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
	}
	err = w.AuditOperation(ctx, func(inner context.Context) error {
		w.Record(inner, &models.AuditLog{Event: "over_capacity"})
		return nil
	}, func(error) bool { return false })
	if !errors.Is(err, audit.ErrUnavailable) {
		t.Fatal("capacity admission falsely acknowledged", err)
	}
	uid = 99
	cancel()
	if services.AuditDroppedEntries.Load() != dropped {
		t.Fatal("durable event counted as lost")
	}
	b, err := repo.Backlog(context.Background())
	if err != nil || b.Pending != 2 {
		t.Fatal("late durable backlog", b, err)
	}
	restarted := services.NewAsyncAuditWriter(repo, repo, config.AuditConfig{BufferSize: 1, FlushBatch: 10})
	restarted.Close()
	rows, err := repo.StreamAll(tenant.WithTenant(context.Background(), "late"), "late")
	if err != nil || len(rows) != 2 {
		t.Fatal("restart lost canceled handler evidence", len(rows), err)
	}
	for _, e := range rows {
		if e.UserID == nil || *e.UserID != 42 || e.Detail != "" || e.ActorID != 42 {
			t.Fatal("mutable/secret context survived")
		}
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	called := false
	err = restarted.AuditOperation(context.Background(), func(context.Context) error { called = true; return nil }, func(error) bool { return false })
	if !errors.Is(err, audit.ErrUnavailable) || called {
		t.Fatal("database outage falsely acknowledged", err)
	}
}
