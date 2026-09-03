package services_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

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

func (m *mockAuditRepo) FindByUserIDPaginated(ctx context.Context, userID uint, page, limit int) ([]models.AuditLog, int64, error) {
	return nil, 0, nil
}

func (m *mockAuditRepo) AnonymizeUser(ctx context.Context, userID uint) error {
	return nil
}

func (m *mockAuditRepo) StreamAll(ctx context.Context, tenantID string) ([]models.AuditLog, error) {
	var out []models.AuditLog
	for _, r := range m.recorded {
		if r != nil {
			out = append(out, *r)
		}
	}
	return out, nil
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

// gatingInserter blocks inside its FIRST BatchInsert call until released,
// letting tests pin the worker deterministically while the buffer overflows.
type gatingInserter struct {
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	inserted int
}

func (g *gatingInserter) BatchInsert(ctx context.Context, entries []*models.AuditLog) int {
	g.once.Do(func() {
		g.entered <- struct{}{}
		<-g.release
	})
	g.inserted += len(entries)
	return len(entries)
}

// TestAsyncAuditWriter_CountsDroppedEntries_A6 — A6: entries dropped on a
// full buffer must be counted in AuditDroppedEntries, not just logged.
func TestAsyncAuditWriter_CountsDroppedEntries_A6(t *testing.T) {
	repo := &mockAuditRepo{}
	gate := &gatingInserter{entered: make(chan struct{}), release: make(chan struct{})}
	writer := services.NewAsyncAuditWriter(repo, gate, config.AuditConfig{BufferSize: 2, FlushBatch: 1})

	before := services.AuditDroppedEntries.Load()
	writer.Record(context.Background(), &models.AuditLog{Event: "first"})
	<-gate.entered // worker is now blocked inside BatchInsert
	// Buffer holds 2; of the next 5 entries exactly 3 must be dropped.
	for i := 0; i < 5; i++ {
		writer.Record(context.Background(), &models.AuditLog{Event: "overflow"})
	}
	close(gate.release)
	writer.Close()

	if got := services.AuditDroppedEntries.Load() - before; got != 3 {
		t.Fatalf("dropped counter delta = %d, want 3", got)
	}
}

// TestAsyncAuditWriter_TruncatesDetail_A6 — A6: Detail longer than the
// audit_logs.detail column (500) must be truncated at the writer so a long
// message cannot fail the batch INSERT. Truncation lands on a rune boundary.
func TestAsyncAuditWriter_TruncatesDetail_A6(t *testing.T) {
	repo := &mockAuditRepo{}
	inserter := &mockBatchInserter{}
	writer := services.NewAsyncAuditWriter(repo, inserter, config.AuditConfig{BufferSize: 4, FlushBatch: 2})

	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'x'
	}
	multibyte := string(long) + strings.Repeat("é", 10) // overlong AND multibyte tail
	writer.Record(context.Background(), &models.AuditLog{Event: "trunc", Detail: multibyte})
	writer.Close()

	if len(inserter.inserted) != 1 {
		t.Fatalf("inserted %d entries, want 1", len(inserter.inserted))
	}
	d := inserter.inserted[0].Detail
	if len(d) > 500 {
		t.Fatalf("Detail length = %d, want <= 500", len(d))
	}
	if !utf8.ValidString(d) {
		t.Fatal("truncated Detail must remain valid UTF-8")
	}
}

// lossyInserter reports one fewer insert than attempted.
type lossyInserter struct{ attempted, reported int }

func (l *lossyInserter) BatchInsert(ctx context.Context, entries []*models.AuditLog) int {
	l.attempted += len(entries)
	l.reported++
	return len(entries) - 1
}

// TestAsyncAuditWriter_CountsInsertLosses_A6 — A6: rows the batch INSERT
// failed to persist must be counted and logged, not silently disappear.
func TestAsyncAuditWriter_CountsInsertLosses_A6(t *testing.T) {
	repo := &mockAuditRepo{}
	lossy := &lossyInserter{}
	writer := services.NewAsyncAuditWriter(repo, lossy, config.AuditConfig{BufferSize: 4, FlushBatch: 1})

	before := services.AuditDroppedEntries.Load()
	writer.Record(context.Background(), &models.AuditLog{Event: "one"})
	writer.Close()

	if got := services.AuditDroppedEntries.Load() - before; got != 1 {
		t.Fatalf("insert-loss counter delta = %d, want 1", got)
	}
}
