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

// flushTimeout bounds a single batch INSERT so a wedged MySQL (LB silently
// dropping, TCP retransmitting for minutes) can never park the worker — or
// hang process shutdown — indefinitely. A flush that hits the cap counts the
// whole batch as dropped (visible in AuditDroppedEntries).
const flushTimeout = 10 * time.Second

// AsyncAuditWriter wraps an AuditRepo to provide asynchronous, non-blocking
// buffered writes. It satisfies the AuditRepo interface.
type AsyncAuditWriter struct {
	repo       AuditRepo
	inserter   BatchInserter
	buffer     chan *models.AuditLog
	flushBatch int
	stopCh     chan struct{} // Close signals shutdown here; the buffer is NEVER closed
	doneCh     chan struct{} // closed by the worker when it has fully drained
	syncMode   bool
	closing    atomic.Bool // Record consults this to avoid racing a shutdown drain
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
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
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
// here — the single choke point both modes flow through. After Close, the
// entry is written synchronously (best effort) instead of panicking on a
// drained channel — straggler handlers that finish after srv.Shutdown keep
// producing audit rows, and they must not die for it.
func (w *AsyncAuditWriter) Record(ctx context.Context, entry *models.AuditLog) {
	truncateDetail(entry)
	if w.syncMode {
		w.repo.Record(ctx, entry)
		return
	}
	if w.closing.Load() {
		w.repo.Record(ctx, entry) // shutdown drain in progress — write direct
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
// or every 500ms. It exits when Close signals stopCh and the buffer has been
// drained; a panic inside the insert path is recovered so the worker (and
// with it the shutdown drain) can never die silently.
func (w *AsyncAuditWriter) worker() {
	defer close(w.doneCh)
	defer func() {
		if r := recover(); r != nil {
			slog.Error("audit worker panicked", "panic", r)
		}
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var batch []*models.AuditLog

	flush := func() {
		if len(batch) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
			n := w.inserter.BatchInsert(ctx, batch)
			cancel()
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

	drainAndExit := func() {
		// Non-blocking drain of whatever remains buffered.
		for {
			select {
			case entry := <-w.buffer:
				batch = append(batch, entry)
				if len(batch) >= w.flushBatch {
					flush()
				}
			default:
				flush()
				return
			}
		}
	}

	for {
		select {
		case entry := <-w.buffer:
			batch = append(batch, entry)
			if len(batch) >= w.flushBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stopCh:
			drainAndExit()
			return
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

// Close stops accepting new async entries, signals the worker to drain, and
// waits — bounded by closeWaitTimeout so a wedged DB cannot hang process
// shutdown forever (the orchestrator would SIGKILL and the buffered rows
// would be lost anyway; a loud log beats a silent hang).
func (w *AsyncAuditWriter) Close() {
	if w.syncMode {
		return
	}
	w.closing.Store(true)
	close(w.stopCh)
	select {
	case <-w.doneCh:
	case <-time.After(closeWaitTimeout):
		slog.Error("audit worker did not drain in time — buffered entries may be lost",
			"buffered", len(w.buffer))
	}
}

// closeWaitTimeout bounds the shutdown wait in Close.
const closeWaitTimeout = 10 * time.Second
