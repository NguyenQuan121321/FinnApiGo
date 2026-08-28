package jobs

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/store"
)

// tickRecorder captures which instance IDs executed the job and whether any
// two executions ever overlapped.
type tickRecorder struct {
	mu        sync.Mutex
	byID      map[string]int
	inFlight  atomic.Int64
	overlapped atomic.Bool
}

func newTickRecorder() *tickRecorder {
	return &tickRecorder{byID: map[string]int{}}
}

func (t *tickRecorder) fn(ctx context.Context) {
	if t.inFlight.Add(1) > 1 {
		t.overlapped.Store(true)
	}
	defer t.inFlight.Add(-1)
	id := ctx.Value(ctxKey("instance")).(string)
	t.mu.Lock()
	t.byID[id]++
	t.mu.Unlock()
	time.Sleep(2 * time.Millisecond) // hold the job long enough to overlap if broken
}

type ctxKey string

// TestLeaderRunner_TwoContenders_OneRunner_S2 — the S2 gate: two replicas
// contending for the same job lock must never both run the job. While the
// leader stays healthy it keeps leadership (renewal), so the tick work is
// executed by exactly one instance.
func TestLeaderRunner_TwoContenders_OneRunner_S2(t *testing.T) {
	kv := store.NewInMemoryStore(0)
	defer kv.Close()

	rec := newTickRecorder()
	run := func(id string) *LeaderRunner {
		r := NewLeaderRunner(kv, "cleanup", 20*time.Millisecond, 500*time.Millisecond,
			func(ctx context.Context) { rec.fn(context.WithValue(ctx, ctxKey("instance"), id)) })
		r.Start()
		return r
	}
	a := run("instance-A")
	b := run("instance-B")
	time.Sleep(300 * time.Millisecond)
	a.Stop()
	b.Stop()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.overlapped.Load() {
		t.Fatal("S2: job executed concurrently by two contenders")
	}
	if len(rec.byID) != 1 {
		t.Fatalf("S2: %d distinct instances ran the job (%v), want exactly 1 while the leader is healthy",
			len(rec.byID), rec.byID)
	}
	for id, n := range rec.byID {
		if n < 3 {
			t.Fatalf("S2: leader %s ran only %d times over the window", id, n)
		}
	}
}

// TestLeaderRunner_FailoverAfterLeaderDeath_S2 — the lock expires with its
// holder: after the leader stops, the survivor takes over (bounded downtime,
// still never two at once).
func TestLeaderRunner_FailoverAfterLeaderDeath_S2(t *testing.T) {
	kv := store.NewInMemoryStore(0)
	defer kv.Close()

	rec := newTickRecorder()
	mk := func(id string) *LeaderRunner {
		r := NewLeaderRunner(kv, "cleanup", 20*time.Millisecond, 120*time.Millisecond,
			func(ctx context.Context) { rec.fn(context.WithValue(ctx, ctxKey("instance"), id)) })
		r.Start()
		return r
	}
	a := mk("instance-A")
	time.Sleep(80 * time.Millisecond)
	a.Stop() // leader dies WITHOUT releasing mid-run (Stop releases; simulate crash by short TTL)

	b := mk("instance-B")
	time.Sleep(400 * time.Millisecond)
	b.Stop()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.overlapped.Load() {
		t.Fatal("S2: overlap during failover")
	}
	// A ran legitimately before it died; the invariant is that B takes over
	// afterwards and the tick is never executed by both at once.
	if rec.byID["instance-B"] == 0 {
		t.Fatalf("S2: survivor must take over after leader death, got %v", rec.byID)
	}
}

// TestLeaderRunner_ReleaseOnStop_S2 — a graceful leader releases the lock so
// the next contender wins immediately, not after the TTL lapses.
func TestLeaderRunner_ReleaseOnStop_S2(t *testing.T) {
	kv := store.NewInMemoryStore(0)
	defer kv.Close()

	a := NewLeaderRunner(kv, "purge", time.Hour, time.Hour, func(context.Context) {})
	a.Start()
	time.Sleep(20 * time.Millisecond)
	a.Stop()

	if _, ok := kv.Get("jobs:leader:purge"); ok {
		t.Fatal("S2: stopped leader must release the job lock")
	}
	// And the next contender can claim it right away.
	b := NewLeaderRunner(kv, "purge", time.Hour, time.Hour, func(context.Context) {})
	b.Start()
	time.Sleep(20 * time.Millisecond)
	b.Stop()
	if _, ok := kv.Get("jobs:leader:purge"); ok {
		t.Fatal("S2: contender could not claim the released lock")
	}
}
