// Package store defines a small key-value abstraction with TTL support.
//
// It is the seam that lets rate-limit counters (middleware) and the
// single-use-token store (services) work in two modes:
//
//   - single-instance development / CI:  InMemoryStore (this package)
//   - multi-instance production:        a future RedisStore implementing Store
//
// Nothing in the app calls Redis directly. A Redis-backed implementation can
// be added later without touching any call site — it only has to satisfy this
// interface. Activating it is driven by config (REDIS_URL).
package store

import (
	"sync"
	"time"
)

// Store is the contract consumed by rate limiters and token-replay stores.
// All methods must be safe for concurrent use.
//
// Semantics:
//   - Get returns the value and whether the key existed (and was not expired).
//   - Set writes a value with a TTL; a zero TTL means "no expiry".
//   - SetNX sets only if absent and returns whether it performed the write —
//     this is the atomic primitive used for single-use token enforcement and
//     for fixed-window counters.
//   - IncrBy atomically adds delta to a numeric value (treating missing keys
//     as 0) and returns the new value. Used for rate-limit counters and
//     per-account/per-IP attempt counters.
//   - Delete removes a key (idempotent).
type Store interface {
	Get(key string) (any, bool)
	Set(key string, value any, ttl time.Duration)
	SetNX(key string, value any, ttl time.Duration) bool
	IncrBy(key string, delta int64, ttl time.Duration) int64
	Delete(key string)
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
// (expired entries are still reaped lazily on Get/SetNX/IncrBy).
func NewInMemoryStore(sweepInterval time.Duration) *InMemoryStore {
	s := &InMemoryStore{
		data:   make(map[string]entry),
		now:    time.Now,
		stopCh: make(chan struct{}),
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

// IncrBy atomically adds delta to the numeric value at key (missing = 0),
// applies ttl (refreshed on every call), and returns the new value.
func (s *InMemoryStore) IncrBy(key string, delta int64, ttl time.Duration) int64 {
	now := s.now()
	var exp time.Time
	if ttl > 0 {
		exp = now.Add(ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var current int64
	if e, ok := s.data[key]; ok && !e.expired(now) {
		if n, ok := e.value.(int64); ok {
			current = n
		}
	}
	current += delta
	s.data[key] = entry{value: current, exp: exp}
	return current
}

// Delete removes key (idempotent).
func (s *InMemoryStore) Delete(key string) {
	s.mu.Lock()
	delete(s.data, key)
	s.mu.Unlock()
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

func (s *InMemoryStore) sweep() {
	now := s.now()
	s.mu.Lock()
	for k, e := range s.data {
		if e.expired(now) {
			delete(s.data, k)
		}
	}
	s.mu.Unlock()
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
