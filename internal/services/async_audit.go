package services

import (
	"context"
	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/database"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
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
type durableAuditStore interface {
	Admit(context.Context, *models.AuditLog) error
	Dispatch(context.Context, int) (int, error)
	AuditOperation(context.Context, func(context.Context) error, func(error) bool) error
}

var AuditAdmissions atomic.Int64
var AuditAdmissionFailures atomic.Int64
var AuditDelivered atomic.Int64
var AuditDeliveryFailures atomic.Int64
var AuditWakeupCoalesced atomic.Int64
var AuditBacklogPending atomic.Int64
var AuditBacklogDead atomic.Int64
var AuditOldestAgeSeconds atomic.Int64

type AsyncAuditWriter struct {
	durable    durableAuditStore
	closeOnce  sync.Once
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
	if durable, ok := repo.(durableAuditStore); ok {
		w := &AsyncAuditWriter{repo: repo, inserter: inserter, durable: durable, syncMode: cfg.BufferSize <= 0, buffer: make(chan *models.AuditLog, 1), flushBatch: min(max(cfg.FlushBatch, 1), 1000), stopCh: make(chan struct{}), doneCh: make(chan struct{})}
		go w.durableWorker()
		return w
	}

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
	if w.durable != nil {
		err := w.durable.Admit(ctx, entry)
		if err != nil {
			AuditAdmissionFailures.Add(1)
			if op := database.CurrentOperation(ctx); op != nil {
				op.Fail(audit.ErrUnavailable)
			}
			slog.Error("audit admission failed", "code", "admission_unavailable")
			return
		}
		AuditAdmissions.Add(1)
		if w.syncMode && database.CurrentOperation(ctx) == nil {
			_, _ = w.durable.Dispatch(ctx, 1000)
		} else {
			w.wakeup()
		}
		return
	}

	copyEntry := *entry
	copyEntry.TenantID = tenant.FromContext(ctx)
	entry = &copyEntry
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
	if w.syncMode && w.durable == nil {
		return
	}
	w.closing.Store(true)
	w.closeOnce.Do(func() { close(w.stopCh) })
	select {
	case <-w.doneCh:
	case <-time.After(closeWaitTimeout):
		slog.Error("audit worker did not drain in time — pending events remain in durable outbox",
			"buffered", len(w.buffer))
	}
}

// closeWaitTimeout bounds the shutdown wait in Close.
const closeWaitTimeout = 10 * time.Second

// FindByUserIDPaginated delegates query to the underlying repository (P1.4).
func (w *AsyncAuditWriter) FindByUserIDPaginated(ctx context.Context, userID uint, page, limit int) ([]models.AuditLog, int64, error) {
	if w.repo == nil {
		return nil, 0, nil
	}
	return w.repo.FindByUserIDPaginated(ctx, userID, page, limit)
}

// AnonymizeUser delegates GDPR right-to-erasure anonymization to the underlying repository (P1.3).
func (w *AsyncAuditWriter) AnonymizeUser(ctx context.Context, userID uint) error {
	if w.repo == nil {
		return nil
	}
	return w.repo.AnonymizeUser(ctx, userID)
}

// StreamAll delegates audit streaming to the underlying repository (P2.3).
func (w *AsyncAuditWriter) StreamAll(ctx context.Context, tenantID string) ([]models.AuditLog, error) {
	if w.repo == nil {
		return nil, nil
	}
	return w.repo.StreamAll(ctx, tenantID)
}

// AuditOperation propagates admission and commit failures to real service callers.
func (w *AsyncAuditWriter) AuditOperation(ctx context.Context, fn func(context.Context) error, denial func(error) bool) error {
	if w.durable == nil {
		return fn(ctx)
	}
	err := w.durable.AuditOperation(database.WithAsyncDelivery(ctx), fn, denial)
	w.wakeup()
	return err
}
func (w *AsyncAuditWriter) wakeup() {
	select {
	case w.buffer <- nil:
	default:
		AuditWakeupCoalesced.Add(1)
	}
}
func (w *AsyncAuditWriter) durableWorker() {
	defer close(w.doneCh)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	flush := func() {
		ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
		defer cancel()
		n, err := w.durable.Dispatch(ctx, w.flushBatch)
		if stats, ok := w.durable.(interface {
			OutboxStats(context.Context) (int64, int64, time.Duration, error)
		}); ok {
			pending, dead, age, statsErr := stats.OutboxStats(ctx)
			if statsErr == nil {
				AuditBacklogPending.Store(pending)
				AuditBacklogDead.Store(dead)
				AuditOldestAgeSeconds.Store(int64(age.Seconds()))
			}
		}
		AuditDelivered.Add(int64(n))
		if err != nil {
			AuditDeliveryFailures.Add(1)
			slog.Error("audit delivery deferred", "code", "delivery_failed")
		}
	}
	for {
		select {
		case <-ticker.C:
			flush()
		case <-w.buffer:
			flush()
		case <-w.stopCh:
			flush()
			return
		}
	}
}
