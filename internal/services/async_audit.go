package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
)

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
// the entry is dropped to prevent blocking the request, and a warning is logged.
func (w *AsyncAuditWriter) Record(ctx context.Context, entry *models.AuditLog) {
	if w.syncMode {
		w.repo.Record(ctx, entry)
		return
	}

	select {
	case w.buffer <- entry:
	default:
		slog.Error("audit buffer full, dropping entry", "event", entry.Event)
	}
}

// worker reads from the buffer and batch-inserts when flushBatch is reached
// or every 500ms.
func (w *AsyncAuditWriter) worker() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var batch []*models.AuditLog

	flush := func() {
		if len(batch) > 0 {
			w.inserter.BatchInsert(context.Background(), batch)
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

// Close gracefully shuts down the worker by closing the channel and waiting
// for remaining entries to be flushed.
func (w *AsyncAuditWriter) Close() {
	if w.syncMode {
		return
	}
	close(w.buffer)
	<-w.done
}
