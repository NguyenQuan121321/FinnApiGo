// Package jobs provides the leader-election runner for background jobs (S2):
// cleanup/purge work must run on exactly ONE replica even when several
// instances share a store, while remaining trivially correct for the common
// single-instance deployment.
//
// Two control modes (both documented in README):
//
//   - Leader election (default): the lock key `jobs:leader:<name>` is claimed
//     with Store.SetNX (SET NX PX on Redis — atomic multi-instance safe) and
//     renewed by the current leader so leadership stays stable while it is
//     healthy. A dead leader's lock simply expires and a contender takes over.
//   - RUN_JOBS=true: this replica runs the job unconditionally (the minimal
//     single-replica variant — set it on exactly one replica). An explicit
//     RUN_JOBS=false disables the job on that replica entirely.
//
// The async audit writer's flush is deliberately NOT leader-elected: each
// instance must drain its OWN buffered audit entries before shutdown, so
// flushing is per-instance by construction.
package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/finnapigo/finnapigo/internal/store"
)

// Renewer is an OPTIONAL store capability: extending a key's TTL without
// changing its value. Both production stores implement it; minimal test fakes
// may not, in which case the runner falls back to lock expiry + re-acquisition
// (still exactly-one-runner per tick, but leadership may rotate).
type Renewer interface {
	Renew(key string, ttl time.Duration) bool
}

// LeaderRunner executes fn on the interval while this instance holds the job
// lock. Start must be called once; Stop is idempotent.
type LeaderRunner struct {
	kv       store.Store
	name     string
	lockKey  string
	self     string
	interval time.Duration
	lockTTL  time.Duration
	fn       func(ctx context.Context)

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewLeaderRunner builds a runner named name (the lock key derives from it).
// lockTTL bounds how long a dead leader's claim survives; interval is the job
// cadence. fn receives a context canceled on Stop.
func NewLeaderRunner(kv store.Store, name string, interval, lockTTL time.Duration, fn func(ctx context.Context)) *LeaderRunner {
	return &LeaderRunner{
		kv:       kv,
		name:     name,
		lockKey:  "jobs:leader:" + name,
		self:     uuid.NewString(),
		interval: interval,
		lockTTL:  lockTTL,
		fn:       fn,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start launches the election + tick loop. Non-blocking.
func (r *LeaderRunner) Start() {
	go r.loop()
}

// Stop cancels the loop and waits for it to exit. Safe to call multiple times.
func (r *LeaderRunner) Stop() {
	r.stopOnce.Do(func() { close(r.stopCh) })
	<-r.doneCh
}

// isLeader claims or refreshes the job lock and reports whether this instance
// may run the tick.
func (r *LeaderRunner) isLeader() bool {
	if r.kv.SetNX(r.lockKey, r.self, r.lockTTL) {
		return true // freshly acquired
	}
	// Already locked — if it is OUR lock, renew it (keeps leadership stable).
	if owner, ok := r.kv.Get(r.lockKey); ok && owner == r.self {
		if renewer, canRenew := r.kv.(Renewer); canRenew {
			return renewer.Renew(r.lockKey, r.lockTTL)
		}
		// Without Renew the claim lapses at lockTTL and re-acquisition races
		// cleanly: exactly one SetNX wins.
	}
	return false
}

func (r *LeaderRunner) loop() {
	defer close(r.doneCh)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			if r.isSelfLeader() {
				r.kv.Delete(r.lockKey) // release promptly so failover is fast
			}
			return
		case <-ticker.C:
			if !r.isLeader() {
				continue
			}
			func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				r.fn(ctx)
			}()
		}
	}
}

func (r *LeaderRunner) isSelfLeader() bool {
	owner, ok := r.kv.Get(r.lockKey)
	return ok && owner == r.self
}

// RunWhileLeader is the RUN_JOBS=true path: run fn unconditionally on this
// replica with the same cadence, no election. Used when the operator pins
// background work to exactly one replica explicitly.
func RunWhileLeader(ctx context.Context, interval time.Duration, fn func(ctx context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}
