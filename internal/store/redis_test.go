package store

import (
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

// TestRedisStore_OutageSplitFailureSemantics_A1 — A1: with Redis unreachable,
// rate COUNTERS fail OPEN (IncrBy returns 0 — a Redis outage must not become
// an auth outage; the caller's local fallback takes over) while single-use
// guards fail CLOSED (SetNX returns false — a consumed token must never
// replay). Both directions count into StoreErrors. This supersedes the
// earlier "IncrBy → MaxInt64 always" contract.
func TestRedisStore_OutageSplitFailureSemantics_A1(t *testing.T) {
	s, mr, cleanup := newMiniredisStore(t)
	// Close only the redis side; cleanup still closes the client.
	mr.Close()
	defer cleanup()

	before := StoreErrors.Load()
	if n := s.IncrBy("counter", 1, time.Minute); n != 0 {
		t.Errorf("IncrBy on dead redis = %d, want 0 (fail open for counters)", n)
	}
	if s.SetNX("guard", "v", time.Minute) {
		t.Error("SetNX on dead redis must return false (fail closed for single-use guards)")
	}
	if dropped := StoreErrors.Load() - before; dropped < 2 {
		t.Errorf("StoreErrors must count every failed op, delta=%d want >= 2", dropped)
	}
}

// TestRedisStore_IncrBy_FixedWindowNotExtended_C4 — C4 regression: the
// counter's TTL must be anchored at the FIRST increment of a window; later
// increments (including denied requests) must not extend it. Otherwise a
// client that keeps hammering stays 429-locked indefinitely.
func TestRedisStore_IncrBy_FixedWindowNotExtended_C4(t *testing.T) {
	s, mr, cleanup := newMiniredisStore(t)
	defer cleanup()

	s.IncrBy("c", 1, time.Second) // window starts at t=0
	mr.FastForward(700 * time.Millisecond)
	if n := s.IncrBy("c", 1, time.Second); n != 2 {
		t.Fatalf("mid-window IncrBy = %d, want 2", n)
	}
	if n := s.IncrBy("c", 1, time.Second); n != 3 {
		t.Fatalf("mid-window IncrBy = %d, want 3", n)
	}
	// 1.1s after the FIRST increment — the window must have elapsed even
	// though later increments happened at t=0.7s.
	mr.FastForward(400 * time.Millisecond)
	if n := s.IncrBy("c", 1, time.Second); n != 1 {
		t.Errorf("counter must reset one window after the first increment, got %d", n)
	}
}

func TestRedisStore_Take(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	if _, ok := s.Take("missing"); ok {
		t.Error("Take on missing key should return false")
	}

	s.Set("key1", "val1", time.Minute)
	got, ok := s.Take("key1")
	if !ok || got != "val1" {
		t.Fatalf("Take = %v, %v; want val1, true", got, ok)
	}
	if _, ok := s.Get("key1"); ok {
		t.Error("key should be deleted after Take")
	}
}

func TestRedisStore_Renew(t *testing.T) {
	s, mr, cleanup := newMiniredisStore(t)
	defer cleanup()

	if s.Renew("missing", time.Minute) {
		t.Error("Renew on missing key should return false")
	}

	s.Set("k", "v", time.Second)
	if !s.Renew("k", 10*time.Minute) {
		t.Fatal("Renew on existing key should return true")
	}
	mr.FastForward(2 * time.Second)
	if _, ok := s.Get("k"); !ok {
		t.Error("key should persist after Renew")
	}
}

func TestRedisStore_RenewIfOwner(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	if s.RenewIfOwner("missing", "owner1", time.Minute) {
		t.Error("RenewIfOwner on missing key should return false")
	}

	s.Set("lock", "owner1", time.Minute)
	if s.RenewIfOwner("lock", "owner2", time.Minute) {
		t.Error("RenewIfOwner with wrong owner should return false")
	}
	if !s.RenewIfOwner("lock", "owner1", time.Minute) {
		t.Fatal("RenewIfOwner with matching owner should return true")
	}
}

func TestRedisStore_DeleteIfOwner(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	if s.DeleteIfOwner("missing", "owner1") {
		t.Error("DeleteIfOwner on missing key should return false")
	}

	s.Set("lock", "owner1", time.Minute)
	if s.DeleteIfOwner("lock", "owner2") {
		t.Error("DeleteIfOwner with wrong owner should return false")
	}
	if !s.DeleteIfOwner("lock", "owner1") {
		t.Fatal("DeleteIfOwner with matching owner should return true")
	}
	if _, ok := s.Get("lock"); ok {
		t.Error("key should be deleted after DeleteIfOwner")
	}
}

func TestRedisStore_NewFromURL(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	store, closeFn, err := NewRedisStoreFromURL("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewRedisStoreFromURL valid: %v", err)
	}
	defer func() { _ = closeFn() }()

	store.Set("url_test", "ok", time.Minute)
	if got, ok := store.Get("url_test"); !ok || got != "ok" {
		t.Fatalf("Get url_test = %v,%v; want ok,true", got, ok)
	}

	// Invalid URL
	if _, _, err := NewRedisStoreFromURL(":::invalid-url:::"); err == nil {
		t.Error("NewRedisStoreFromURL with invalid URL must error")
	}
}

func TestRedisStore_ToRedisValueTypes(t *testing.T) {
	s, _, cleanup := newMiniredisStore(t)
	defer cleanup()

	s.Set("str", "hello", time.Minute)
	s.Set("int", int(42), time.Minute)
	s.Set("int64", int64(999), time.Minute)
	s.Set("bytes", []byte("byte-val"), time.Minute)
	s.Set("other", 3.14, time.Minute)

	if got, _ := s.Get("int"); got != "42" {
		t.Errorf("Get(int) = %v, want 42", got)
	}
	if got, _ := s.Get("int64"); got != "999" {
		t.Errorf("Get(int64) = %v, want 999", got)
	}
	if got, _ := s.Get("bytes"); got != "byte-val" {
		t.Errorf("Get(bytes) = %v, want byte-val", got)
	}
}

func TestRedisStore_DeadRedisErrorBranches(t *testing.T) {
	s, mr, cleanup := newMiniredisStore(t)
	mr.Close()
	defer cleanup()

	// Take on dead redis -> returns false
	if _, ok := s.Take("key"); ok {
		t.Error("Take on dead redis must return false")
	}

	// Set on dead redis -> logs error and records StoreError
	s.Set("key", "val", time.Minute)

	// Renew on dead redis -> returns false
	if s.Renew("key", time.Minute) {
		t.Error("Renew on dead redis must return false")
	}

	// RenewIfOwner on dead redis -> returns false
	if s.RenewIfOwner("key", "owner", time.Minute) {
		t.Error("RenewIfOwner on dead redis must return false")
	}

	// DeleteIfOwner on dead redis -> returns false
	if s.DeleteIfOwner("key", "owner") {
		t.Error("DeleteIfOwner on dead redis must return false")
	}
}
