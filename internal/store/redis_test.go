package store

import (
	"math"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newMiniredisStore starts an in-process Redis (no external server needed) and
// returns a RedisStore backed by it, the miniredis instance (so tests can
// deterministically advance time via FastForward), and a cleanup func.
func newMiniredisStore(t *testing.T) (*RedisStore, *miniredis.Miniredis, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisStore(client)
	return store, mr, func() {
		_ = client.Close()
		mr.Close()
	}
}

// TestRedisStore_SatisfiesContract is a compile-time guard: RedisStore must
// implement the Store interface exactly like InMemoryStore does.
func TestRedisStore_SatisfiesContract(t *testing.T) {
	var _ Store = (*RedisStore)(nil)
	var _ Store = (*InMemoryStore)(nil)
}

func TestRedisStore_SetNX(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	if !s.SetNX("k", "v1", time.Minute) {
		t.Error("first SetNX should succeed")
	}
	if s.SetNX("k", "v2", time.Minute) {
		t.Error("second SetNX on existing key should fail")
	}
	got, ok := s.Get("k")
	if !ok || got != "v1" {
		t.Errorf("Get = %v,%v; want v1,true", got, ok)
	}
}

func TestRedisStore_IncrBy(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	if n := s.IncrBy("c", 1, time.Minute); n != 1 {
		t.Errorf("IncrBy 1 = %d, want 1", n)
	}
	if n := s.IncrBy("c", 1, time.Minute); n != 2 {
		t.Errorf("IncrBy 1 = %d, want 2", n)
	}
	if n := s.IncrBy("c", 5, time.Minute); n != 7 {
		t.Errorf("IncrBy 5 = %d, want 7", n)
	}
}

// TestRedisStore_IncrByTTLExpiry confirms the counter resets after its TTL.
// IncrBy refreshes the TTL on every call (sliding window), so we advance
// miniredis's clock (deterministic — no flaky real sleeps) past the idle window
// and assert a fresh IncrBy starts from 0.
func TestRedisStore_IncrByTTLExpiry(t *testing.T) {
	s, mr, cleanup := newMiniredisStore(t)
	defer cleanup()

	s.IncrBy("c", 1, time.Second)
	if n := s.IncrBy("c", 1, time.Second); n != 2 {
		t.Fatalf("before TTL: IncrBy = %d, want 2", n)
	}
	// Advance the idle window with NO intervening IncrBy (any IncrBy would
	// reset the TTL). FastForward deterministically expires keys.
	mr.FastForward(2 * time.Second)
	if n := s.IncrBy("c", 1, time.Second); n != 1 {
		t.Errorf("after TTL idle: IncrBy = %d, want 1", n)
	}
}

func TestRedisStore_GetDelete(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	s.Set("k", "v", time.Minute)
	if got, ok := s.Get("k"); !ok || got != "v" {
		t.Errorf("Get = %v,%v; want v,true", got, ok)
	}
	s.Delete("k")
	if _, ok := s.Get("k"); ok {
		t.Error("Delete should remove the key")
	}
	// Delete of missing key is a no-op.
	s.Delete("missing")
}

func TestRedisStore_SetNoExpiry(t *testing.T) {
	s, mr, cleanup := newMiniredisStore(t)
	defer cleanup()

	// ttl 0 means "no expiry" — the key must survive a time advance that
	// would have expired a real TTL.
	s.Set("forever", "1", 0)
	mr.FastForward(time.Second)
	if _, ok := s.Get("forever"); !ok {
		t.Error("key with ttl=0 must persist")
	}
}

// TestRedisStore_GetMissingReturnsFalse ensures an absent key (never written,
// or naturally expired) reports absent rather than zero-value.
func TestRedisStore_GetMissingReturnsFalse(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	if _, ok := s.Get("nope"); ok {
		t.Error("absent key must report absent")
	}
}

// TestRedisStore_FailClosedOnOutage proves the store DENIES (not allows) when
// Redis is unreachable: IncrBy returns MaxInt64 so every rate limiter reading
// it rejects the request, and SetNX returns false so single-use guards block.
func TestRedisStore_FailClosedOnOutage(t *testing.T) {
	s, mr, cleanup := newMiniredisStore(t)
	// Close only the redis side; cleanup still closes the client.
	mr.Close()
	defer cleanup()

	if n := s.IncrBy("c", 1, time.Minute); n != math.MaxInt64 {
		t.Errorf("IncrBy on dead redis = %d, want MaxInt64 (fail closed)", n)
	}
	if s.SetNX("k", "v", time.Minute) {
		t.Error("SetNX on dead redis must return false (fail closed)")
	}
}
