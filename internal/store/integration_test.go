//go:build integration

// Redis-backed integration tests (T1) — same layer as the CI integration job:
// a REAL Redis (docker container locally, or the CI service container).
//
//	TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
//		go test -tags=integration ./internal/store/ -v -count=1
package store

import (
	"os"
	"testing"
	"time"
)

// TestRedisStore_Integration_FixedWindowAndGuards_T1 — the C4/A1 semantics
// the unit tests prove against miniredis, re-proven against a real Redis:
// the window TTL anchors at the first increment, and SetNX stays exclusive.
func TestRedisStore_Integration_FixedWindowAndGuards_T1(t *testing.T) {
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set — skipping Redis integration test")
	}
	rs, closeFn, err := NewRedisStoreFromURL(url)
	if err != nil {
		t.Fatalf("connect redis: %v", err)
	}
	defer func() { _ = closeFn() }()

	stamp := time.Now().Format("150405.000000000")
	windowKey := "integration:window:" + stamp
	rs.Delete(windowKey)
	t.Cleanup(func() { rs.Delete(windowKey) })

	if n := rs.IncrBy(windowKey, 1, 60*time.Millisecond); n != 1 {
		t.Fatalf("first incr = %d, want 1", n)
	}
	if n := rs.IncrBy(windowKey, 2, 60*time.Millisecond); n != 3 {
		t.Fatalf("second incr = %d, want 3 (window anchored, not reset)", n)
	}
	// Fixed window: after expiry the counter restarts from the next delta.
	time.Sleep(120 * time.Millisecond)
	if n := rs.IncrBy(windowKey, 5, 60*time.Millisecond); n != 5 {
		t.Fatalf("post-expiry incr = %d, want 5 (fresh window)", n)
	}

	// Single-use guard semantics: exactly one SetNX wins.
	guardKey := "integration:guard:" + stamp
	rs.Delete(guardKey)
	t.Cleanup(func() { rs.Delete(guardKey) })
	if !rs.SetNX(guardKey, "1", time.Minute) {
		t.Fatal("first SetNX must win")
	}
	if rs.SetNX(guardKey, "1", time.Minute) {
		t.Fatal("second SetNX must lose — single-use guard would replay")
	}
}

// TestIntegrationEnvironmentGuard makes silent integration skips impossible:
// in CI the service env MUST be provided — a missing variable fails the job
// instead of letting every integration test skip its way to green (the
// apidrift "the check itself is broken" doctrine applied to integration).
func TestIntegrationEnvironmentGuard(t *testing.T) {
	if os.Getenv("TEST_MYSQL_DSN") == "" || os.Getenv("TEST_REDIS_URL") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI must provide TEST_MYSQL_DSN and TEST_REDIS_URL — integration tests silently skipping to green is forbidden")
		}
		t.Skip("integration env not set (local run)")
	}
}
