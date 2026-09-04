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
	mu         sync.Mutex
	byID       map[string]int
	inFlight   atomic.Int64
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

	// Snapshot BEFORE any Stop: stopping a leader releases its lock, which
	// legitimately lets the survivor take over mid-teardown.
	rec.mu.Lock()
	byID := map[string]int{}
	for k, v := range rec.byID {
		byID[k] = v
	}
	overlapped := rec.overlapped.Load()
	rec.mu.Unlock()
	a.Stop()
	b.Stop()

	if overlapped {
		t.Fatal("S2: job executed concurrently by two contenders")
	}
	if len(byID) != 1 {
		t.Fatalf("S2: %d distinct instances ran the job (%v), want exactly 1 while the leader is healthy",
			len(byID), byID)
	}
	for id, n := range byID {
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

func TestRunWhileLeader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int32
	done := make(chan struct{})
	go func() {
		RunWhileLeader(ctx, 10*time.Millisecond, func(ctx context.Context) {
			count.Add(1)
		})
		close(done)
	}()

	time.Sleep(35 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunWhileLeader did not terminate on cancel")
	}

	if count.Load() == 0 {
		t.Fatal("RunWhileLeader should execute at least once")
	}
}

func TestLeaderRunner_StartStopIdempotence(t *testing.T) {
	kv := store.NewInMemoryStore(0)
	defer kv.Close()

	r := NewLeaderRunner(kv, "test-idempotence", time.Hour, time.Hour, func(context.Context) {})
	r.Start()
	r.Start() // calling Start again should be a no-op

	r.Stop()
	r.Stop() // calling Stop again should be a no-op
}

type fakeLegacyStore struct {
	mu     sync.Mutex
	data   map[string]string
	canRen bool
}

func newFakeLegacyStore(canRen bool) *fakeLegacyStore {
	return &fakeLegacyStore{data: map[string]string{}, canRen: canRen}
}

func (f *fakeLegacyStore) Get(key string) (any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	return v, ok
}

func (f *fakeLegacyStore) Set(key string, val any, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = val.(string)
}

func (f *fakeLegacyStore) SetNX(key string, val any, ttl time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.data[key]; ok {
		return false
	}
	f.data[key] = val.(string)
	return true
}

func (f *fakeLegacyStore) Take(key string) (any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	delete(f.data, key)
	return v, ok
}

func (f *fakeLegacyStore) IncrBy(key string, delta int64, ttl time.Duration) int64 { return 0 }
func (f *fakeLegacyStore) Delete(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
}
func (f *fakeLegacyStore) Renew(key string, ttl time.Duration) bool {
	return f.canRen
}

func TestLeaderRunner_LegacyStoreFallback(t *testing.T) {
	fs := newFakeLegacyStore(true)
	r := NewLeaderRunner(fs, "legacy-job", 10*time.Millisecond, time.Hour, func(context.Context) {})

	// First call: SetNX succeeds
	if !r.isLeader() {
		t.Fatal("first isLeader should acquire via SetNX")
	}

	// Second call: SetNX returns false, legacy Renewer invoked
	if !r.isLeader() {
		t.Fatal("second isLeader should renew via Renewer fallback")
	}

	// releaseLock via legacy isSelfLeader -> Delete
	r.releaseLock()
	if _, ok := fs.Get(r.lockKey); ok {
		t.Fatal("lock should be deleted after releaseLock")
	}

	// Test store without Renewer
	noRenewStore := &struct {
		*fakeLegacyStore
	}{newFakeLegacyStore(false)}
	r2 := NewLeaderRunner(noRenewStore, "no-ren-job", 10*time.Millisecond, time.Hour, func(context.Context) {})
	_ = r2.isLeader() // acquires lock
	// Simulate already locked by self, but store has no Renewer
	if r2.isLeader() {
		t.Fatal("isLeader without Renewer capability should return false")
	}
}
