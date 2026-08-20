package store

import (
	"testing"
	"time"
)

// TestInMemoryStore_SetNX proves the atomic primitive that single-use token
// enforcement and fixed-window counters rely on: only the first SetNX wins.
func TestInMemoryStore_SetNX(t *testing.T) {
	s := NewInMemoryStore(0)
	defer s.Close()

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

func TestInMemoryStore_TTLExpiry(t *testing.T) {
	clock := time.Now()
	s := NewInMemoryStore(0)
	defer s.Close()
	s.now = func() time.Time { return clock }

	s.Set("k", 1, 10*time.Millisecond)
	if _, ok := s.Get("k"); !ok {
		t.Error("should exist before TTL")
	}
	clock = clock.Add(20 * time.Millisecond)
	if _, ok := s.Get("k"); ok {
		t.Error("should be expired after TTL")
	}
}

func TestInMemoryStore_IncrBy(t *testing.T) {
	s := NewInMemoryStore(0)
	defer s.Close()

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

// TestInMemoryStore_TTLExpiryAfterIncrBy confirms the counter TTL is refreshed
// on each IncrBy (sliding window) and that expiry clears the counter.
func TestInMemoryStore_TTLExpiryAfterIncrBy(t *testing.T) {
	clock := time.Now()
	s := NewInMemoryStore(0)
	defer s.Close()
	s.now = func() time.Time { return clock }

	s.IncrBy("c", 1, 10*time.Millisecond)
	clock = clock.Add(20 * time.Millisecond)
	// After TTL, a fresh IncrBy must start from 0, not accumulate.
	if n := s.IncrBy("c", 1, 10*time.Millisecond); n != 1 {
		t.Errorf("IncrBy after expiry = %d, want 1", n)
	}
}

func TestInMemoryStore_Delete(t *testing.T) {
	s := NewInMemoryStore(0)
	defer s.Close()

	s.Set("k", "v", 0)
	s.Delete("k")
	if _, ok := s.Get("k"); ok {
		t.Error("Delete should remove the key")
	}
	// Delete of missing key is a no-op (no panic).
	s.Delete("missing")
}

func TestInMemoryStore_SweeperReapsExpired(t *testing.T) {
	// Use a real short interval and real clock.
	s := NewInMemoryStore(20 * time.Millisecond)
	defer s.Close()

	s.Set("k", "v", 30*time.Millisecond)
	time.Sleep(80 * time.Millisecond)

	s.mu.Lock()
	_, present := s.data["k"]
	s.mu.Unlock()
	if present {
		t.Error("sweeper should have reaped the expired key")
	}
}

// TestInMemoryStore_IncrBy_FixedWindowNotExtended_C4 — C4 regression, mirror
// of the Redis test: the TTL anchors at the first increment and later
// increments must not extend the window.
func TestInMemoryStore_IncrBy_FixedWindowNotExtended_C4(t *testing.T) {
	clock := time.Now()
	s := NewInMemoryStore(0, WithClock(func() time.Time { return clock }))
	defer s.Close()

	if n := s.IncrBy("c", 1, time.Minute); n != 1 {
		t.Fatalf("IncrBy = %d, want 1", n)
	}
	clock = clock.Add(30 * time.Second)
	if n := s.IncrBy("c", 1, time.Minute); n != 2 {
		t.Fatalf("mid-window IncrBy = %d, want 2", n)
	}
	clock = clock.Add(31 * time.Second) // 61s after the first increment
	if n := s.IncrBy("c", 1, time.Minute); n != 1 {
		t.Errorf("counter must reset one window after the first increment, got %d", n)
	}
}
