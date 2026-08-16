package services

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
)

// maxAuditDetail matches the audit_logs.detail column size (500). Longer
// values are truncated at the writer so a chatty Detail can never make the
// whole batch INSERT fail (A6).
const maxAuditDetail = 500

// AuditDroppedEntries counts audit entries lost despite best-effort delivery:
// buffer overflows AND batch-insert failures (A6). Exposed for metrics — a
// climbing counter means audit coverage is degrading.
var AuditDroppedEntries atomic.Int64

// BatchInserter defines the bulk write method needed by the async worker.
type BatchInserter interface {
	BatchInsert(ctx context.Context, entries []*models.AuditLog) int
}

// AsyncAuditWriter wraps an AuditRepo to provide asynchronous, non-blocking
// buffered writes. It satisfies the AuditRepo interface.
type AsyncAuditWriter struct {
	repo       AuditRepo
	inserter   BatchInserter
	buffer     chan *models.AuditLog
	flushBatch int
	done       chan struct{}
	syncMode   bool
}

// NewAsyncAuditWriter creates a new AsyncAuditWriter. If cfg.BufferSize is 0,
// it falls back to synchronous mode.
func NewAsyncAuditWriter(repo AuditRepo, inserter BatchInserter, cfg config.AuditConfig) *AsyncAuditWriter {
	if cfg.BufferSize <= 0 {
		return &AsyncAuditWriter{
			repo:     repo,
			syncMode: true,
		}
	}

	w := &AsyncAuditWriter{
		repo:       repo,
		inserter:   inserter,
		buffer:     make(chan *models.AuditLog, cfg.BufferSize),
		flushBatch: cfg.FlushBatch,
		done:       make(chan struct{}),
	}

	if w.flushBatch <= 0 {
		w.flushBatch = 64
	}

	go w.worker()

	return w
}

// Record queues the audit log for asynchronous insertion. If the buffer is full,
// the entry is dropped to prevent blocking the request; the drop is counted in
// AuditDroppedEntries and logged (A6). Detail is truncated to the column size
// here — the single choke point both modes flow through.
func (w *AsyncAuditWriter) Record(ctx context.Context, entry *models.AuditLog) {
	truncateDetail(entry)
	if w.syncMode {
		w.repo.Record(ctx, entry)
		return
	}

	select {
	case w.buffer <- entry:
	default:
		AuditDroppedEntries.Add(1)
		slog.Error("audit buffer full, dropping entry", "event", entry.Event)
	}
}

// truncateDetail caps entry.Detail at the audit_logs.detail column size,
// backing off to the last rune boundary so the value stays valid UTF-8 (a
// mid-rune cut would make MySQL reject the whole INSERT).
func truncateDetail(entry *models.AuditLog) {
	if len(entry.Detail) <= maxAuditDetail {
		return
	}
	d := entry.Detail[:maxAuditDetail]
	for len(d) > 0 && !utf8.ValidString(d) {
		d = d[:len(d)-1]
	}
	entry.Detail = d
}

// worker reads from the buffer and batch-inserts when flushBatch is reached
// or every 500ms.
func (w *AsyncAuditWriter) worker() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var batch []*models.AuditLog

	flush := func() {
		if len(batch) > 0 {
			n := w.inserter.BatchInsert(context.Background(), batch)
			if lost := len(batch) - n; lost > 0 {
				// A6 — partial/failed inserts must be visible, not silent
				// gaps in the audit trail.
				AuditDroppedEntries.Add(int64(lost))
				slog.Error("audit batch insert lost entries",
					"attempted", len(batch), "inserted", n, "lost", lost)
			}
			batch = nil
		}
	}

	for {
		select {
		case entry, ok := <-w.buffer:
			if !ok {
				// Channel closed, flush remaining and exit
				flush()
				close(w.done)
				return
			}
			batch = append(batch, entry)
			if len(batch) >= w.flushBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Buffered reports how many entries currently wait in the async buffer (0 in
// sync mode) — the depth gauge for the Prometheus endpoint (P2).
func (w *AsyncAuditWriter) Buffered() int {
	if w.syncMode || w.buffer == nil {
		return 0
	}
	return len(w.buffer)
}

// Close gracefully shuts down the worker by closing the channel and waiting
// for remaining entries to be flushed.
func (w *AsyncAuditWriter) Close() {
	if w.syncMode {
		return
	}
	close(w.buffer)
	<-w.done
}
