package services_test

import (
	"context"
	"testing"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/services"
)

type mockBatchInserter struct {
	inserted []*models.AuditLog
}

func (m *mockBatchInserter) BatchInsert(ctx context.Context, entries []*models.AuditLog) int {
	m.inserted = append(m.inserted, entries...)
	return len(entries)
}

type mockAuditRepo struct {
	recorded []*models.AuditLog
}

func (m *mockAuditRepo) Record(ctx context.Context, entry *models.AuditLog) {
	m.recorded = append(m.recorded, entry)
}

func TestAsyncAuditWriter(t *testing.T) {
	repo := &mockAuditRepo{}
	inserter := &mockBatchInserter{}
	cfg := config.AuditConfig{
		BufferSize: 10,
		FlushBatch: 5,
	}

	writer := services.NewAsyncAuditWriter(repo, inserter, cfg)

	// Record several entries
	entriesToRecord := 7
	for i := 0; i < entriesToRecord; i++ {
		writer.Record(context.Background(), &models.AuditLog{Event: "test"})
	}

	// Close should flush everything
	writer.Close()

	if len(inserter.inserted) != entriesToRecord {
		t.Fatalf("expected %d inserted, got %d", entriesToRecord, len(inserter.inserted))
	}
}

func TestAsyncAuditWriter_SyncMode(t *testing.T) {
	repo := &mockAuditRepo{}
	inserter := &mockBatchInserter{}
	cfg := config.AuditConfig{
		BufferSize: 0, // 0 triggers sync mode
	}

	writer := services.NewAsyncAuditWriter(repo, inserter, cfg)

	writer.Record(context.Background(), &models.AuditLog{Event: "test_sync"})

	writer.Close()

	if len(repo.recorded) != 1 {
		t.Fatalf("expected 1 recorded, got %d", len(repo.recorded))
	}
	if len(inserter.inserted) != 0 {
		t.Fatalf("expected 0 inserted via batch, got %d", len(inserter.inserted))
	}
}
