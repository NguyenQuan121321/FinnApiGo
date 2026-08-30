// Package store defines a small key-value abstraction with TTL support.
//
// It is the seam that lets rate-limit counters (middleware), the
// single-use-token store (services), and leader-election locks (jobs) work in
// two modes:
//
//   - single-instance development / CI:  InMemoryStore (this package)
//   - multi-instance production:        RedisStore (redis.go, REDIS_URL)
//
// Nothing in the app calls Redis directly. Both implementations satisfy the
// Store interface (plus optional capability interfaces: Renewer,
// OwnerLockManager); activating the Redis mode is driven by config (REDIS_URL).
package store

import (
	"fmt"
	"sync"
	"time"
)

// Store is the contract consumed by rate limiters and token-replay stores.
// All methods must be safe for concurrent use.
//
// Semantics:
//   - Get returns the value and whether the key existed (and was not expired).
//   - Take atomically returns AND deletes the value — the single-use
//     consumption primitive for staged data (WebAuthn challenges, OAuth
//     state). Two concurrent Takes: exactly one wins.
//   - Set writes a value with a TTL; a zero TTL means "no expiry".
//   - SetNX sets only if absent and returns whether it performed the write —
//     this is the atomic primitive used for single-use token enforcement and
//     for fixed-window counters.
//   - IncrBy atomically adds delta to a numeric value (treating missing keys
//     as 0) and returns the new value. The TTL anchors at the first increment
//     of a window and is not refreshed by later increments — fixed-window
//     semantics for rate limits and attempt counters.
//   - Delete removes a key (idempotent).
type Store interface {
	Get(key string) (any, bool)
	Take(key string) (any, bool)
	Set(key string, value any, ttl time.Duration)
	SetNX(key string, value any, ttl time.Duration) bool
	IncrBy(key string, delta int64, ttl time.Duration) int64
	Delete(key string)
}

// OwnerLockManager is an OPTIONAL store capability for leader-election locks:
// compare-and-set TTL renewal and compare-and-set release, both verified
// against the lock OWNER value. Without it, a Get→Renew sequence is a TOCTOU
// race that can extend another instance's freshly acquired lock (split brain).
// Both production stores implement it; minimal test fakes may not, in which
// case the runner falls back to lock expiry + re-acquisition.
type OwnerLockManager interface {
	// RenewIfOwner extends the key's TTL only when the stored value equals
	// owner. Reports whether the renewal happened.
	RenewIfOwner(key, owner string, ttl time.Duration) bool
	// DeleteIfOwner deletes the key only when the stored value equals owner.
	DeleteIfOwner(key, owner string) bool
}

// ----- InMemoryStore -----

// entry holds a value and the moment it expires. zero exp means no expiry.
type entry struct {
	value any
	exp   time.Time // zero value = never expires
}

func (e entry) expired(now time.Time) bool {
	return !e.exp.IsZero() && now.After(e.exp)
}

// InMemoryStore is a goroutine-safe Store backed by a plain map + mutex.
// Expired entries are reaped lazily on access and periodically by a background
// sweeper, so memory stays bounded even under sustained public traffic.
type InMemoryStore struct {
	mu      sync.Mutex
	data    map[string]entry
	now     func() time.Time // injectable clock for tests
	stopCh  chan struct{}
	stopped bool
}

// Option configures an InMemoryStore.
type Option func(*InMemoryStore)

// WithClock injects a clock (useful for tests). Defaults to time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *InMemoryStore) { s.now = now }
}

// NewInMemoryStore constructs an InMemoryStore and starts a background sweeper
// that purges expired keys every sweepInterval. Pass 0 to disable the sweeper
// (expired entries are still reaped lazily on Get/SetNX/IncrBy). Options such
// as WithClock apply before the sweeper starts.
func NewInMemoryStore(sweepInterval time.Duration, opts ...Option) *InMemoryStore {
	s := &InMemoryStore{
		data:   make(map[string]entry),
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	if sweepInterval > 0 {
		go s.sweepLoop(sweepInterval)
	}
	return s
}

// Get returns the value for key, or false if missing/expired.
func (s *InMemoryStore) Get(key string) (any, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return nil, false
	}
	if e.expired(now) {
		delete(s.data, key)
		return nil, false
	}
	return e.value, true
}

// Take atomically returns AND deletes the value for key — one consumer wins.
func (s *InMemoryStore) Take(key string) (any, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return nil, false
	}
	delete(s.data, key)
	if e.expired(now) {
		return nil, false
	}
	return e.value, true
}

// Set writes value with ttl (0 = no expiry).
func (s *InMemoryStore) Set(key string, value any, ttl time.Duration) {
	var exp time.Time
	if ttl > 0 {
		exp = s.now().Add(ttl)
	}
	s.mu.Lock()
	s.data[key] = entry{value: value, exp: exp}
	s.mu.Unlock()
}

// SetNX writes value only if key is absent/unexpired; returns whether it wrote.
func (s *InMemoryStore) SetNX(key string, value any, ttl time.Duration) bool {
	now := s.now()
	var exp time.Time
	if ttl > 0 {
		exp = now.Add(ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[key]; ok && !e.expired(now) {
		return false
	}
	s.data[key] = entry{value: value, exp: exp}
	return true
}

// IncrBy atomically adds delta to the numeric value at key (missing = 0) and
// returns the new value. The TTL anchors at the first increment of a window
// and is NOT refreshed by later increments (fixed-window semantics) — a
// counter always resets one TTL after the window began, even under sustained
// traffic. Used for rate-limit counters and per-account/per-IP attempt
// counters.
func (s *InMemoryStore) IncrBy(key string, delta int64, ttl time.Duration) int64 {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if ok && e.expired(now) {
		ok = false // window elapsed — a fresh one starts below
	}
	if ok {
		var current int64
		if n, isInt := e.value.(int64); isInt {
			current = n
		}
		// Keep the existing expiry: the window is anchored at its first
		// increment and must not be extended by later ones.
		s.data[key] = entry{value: current + delta, exp: e.exp}
		return current + delta
	}
	var exp time.Time
	if ttl > 0 {
		exp = now.Add(ttl)
	}
	s.data[key] = entry{value: delta, exp: exp}
	return delta
}

// Delete removes key (idempotent).
func (s *InMemoryStore) Delete(key string) {
	s.mu.Lock()
	delete(s.data, key)
	s.mu.Unlock()
}

// Renew extends the TTL of an existing key without touching its value
// (jobs.Renewer capability). Returns false when the key is absent — callers
// must re-acquire rather than assume ownership.
func (s *InMemoryStore) Renew(key string, ttl time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok || e.expired(now) {
		return false
	}
	var exp time.Time
	if ttl > 0 {
		exp = now.Add(ttl)
	}
	s.data[key] = entry{value: e.value, exp: exp}
	return true
}

// RenewIfOwner extends the TTL only when the stored value matches owner —
// the atomic compare-and-renew leader locks need (no extend-someone-else's-
// lock race). Returns false when the key is absent or owned by someone else.
func (s *InMemoryStore) RenewIfOwner(key, owner string, ttl time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok || e.expired(now) {
		return false
	}
	if fmt.Sprint(e.value) != owner {
		return false
	}
	if ttl > 0 {
		e.exp = now.Add(ttl)
		s.data[key] = e
	}
	return true
}

// DeleteIfOwner deletes the key only when the stored value matches owner —
// the atomic compare-and-delete release for leader locks (a stopped instance
// can no longer delete a lock another instance just acquired).
func (s *InMemoryStore) DeleteIfOwner(key, owner string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return false
	}
	if fmt.Sprint(e.value) != owner {
		return false
	}
	delete(s.data, key)
	return true
}

// sweepLoop periodically drops expired keys to bound memory.
func (s *InMemoryStore) sweepLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.sweep()
		}
	}
}

// sweep drops expired keys in bounded batches so the mutex is held for a
// capped number of iterations, not across the whole map. A full sweep of a
// huge map while holding the global lock would stall every concurrent
// Get/Set/IncrBy; with batching, live traffic interleaves between batches.
// If the batch limit is hit, remaining expired keys are picked up on the next
// tick (the sweeper runs far more often than keys expire).
func (s *InMemoryStore) sweep() {
	now := s.now()
	const batchSize = 1000
	var toDelete []string

	s.mu.Lock()
	for k, e := range s.data {
		if e.expired(now) {
			toDelete = append(toDelete, k)
		}
		if len(toDelete) >= batchSize {
			break
		}
	}
	for _, k := range toDelete {
		delete(s.data, k)
	}
	s.mu.Unlock()
	// If we hit batchSize, there may be more — the next tick will continue.
}

// Close stops the background sweeper. Safe to call multiple times.
func (s *InMemoryStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	close(s.stopCh)
}
