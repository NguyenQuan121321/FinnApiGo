package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/finnapigo/finnapigo/internal/store"
)

// newS1Router builds one limiter instance behind a gin engine and returns a
// helper that issues a request from a given client IP, reporting the status.
func newS1Router(t *testing.T, kv CounterStore, rps float64, burst int) func(ip string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rl := NewRateLimiter(rps, burst, time.Minute, kv)
	t.Cleanup(func() { rl.Close() })
	r := gin.New()
	r.Use(rl.Handler())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	return func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":12345"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
}

// TestRateLimiter_TwoInstances_SharedRedis_S1 — the S1 gate: with REDIS_URL
// configured, TWO limiter instances sharing one store enforce ONE quota, not
// one quota per replica. A single instance would allow `burst` requests; two
// replicas together must stop at the same total.
func TestRateLimiter_TwoInstances_SharedRedis_S1(t *testing.T) {
	mr := miniredis.RunT(t)
	rs, closeRedis, err := store.NewRedisStoreFromURL("redis://" + mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRedis() })

	// burst=2: a single instance admits exactly 2 requests per window.
	instanceA := newS1Router(t, rs, 1, 2)
	instanceB := newS1Router(t, rs, 1, 2)

	// One client IP spreads requests across both replicas. With burst=2 a
	// single instance would admit TWO requests — and the shared counter
	// admits exactly two TOTAL, no matter which replica they land on.
	if got := instanceA("9.9.9.9"); got != http.StatusNoContent {
		t.Fatalf("A request 1: %d", got)
	}
	if got := instanceB("9.9.9.9"); got != http.StatusNoContent {
		t.Fatalf("B request 1: %d (shared counter must admit it)", got)
	}
	// The quota is exhausted ACROSS the two instances — a per-replica
	// implementation would admit two MORE requests here.
	if got := instanceB("9.9.9.9"); got != http.StatusTooManyRequests {
		t.Fatalf("B request 2: %d, want 429 — per-replica quotas would have admitted it", got)
	}
	if got := instanceA("9.9.9.9"); got != http.StatusTooManyRequests {
		t.Fatalf("A request 2: %d, want 429", got)
	}
	// A different IP is unaffected (per-key isolation intact).
	if got := instanceA("8.8.8.8"); got != http.StatusNoContent {
		t.Fatalf("other IP: %d, want 204", got)
	}
}

// TestRateLimiter_SharedRedis_WindowAnchorSurvivesInstances_S1 — C4 semantics
// hold across replicas: the window is anchored at the FIRST increment (on
// whichever replica saw it) and resets one TTL later even though the denied
// client kept hitting both instances.
func TestRateLimiter_SharedRedis_WindowAnchorSurvivesInstances_S1(t *testing.T) {
	mr := miniredis.RunT(t)
	rs, closeRedis, err := store.NewRedisStoreFromURL("redis://" + mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRedis() })

	// rps=0.05, burst=2 → shared window = burst/rps = 40s.
	instanceA := newS1Router(t, rs, 0.05, 2)
	instanceB := newS1Router(t, rs, 0.05, 2)

	for i := 0; i < 2; i++ {
		instanceA("7.7.7.7")
	}
	if got := instanceB("7.7.7.7"); got != http.StatusTooManyRequests {
		t.Fatalf("over burst: %d", got)
	}
	// Denied traffic 30s in (would refresh a broken TTL).
	mr.FastForward(30 * time.Second)
	for i := 0; i < 4; i++ {
		if got := instanceB("7.7.7.7"); got != http.StatusTooManyRequests {
			t.Fatalf("hammer %d: %d", i, got)
		}
	}
	// Past the 40s anchored window the shared counter resets.
	mr.FastForward(11 * time.Second)
	if got := instanceA("7.7.7.7"); got != http.StatusNoContent {
		t.Fatalf("after window: %d, want 204", got)
	}
}

// TestRateLimiter_SharedRedis_Outage_LocalFallback_S1 — A1 under S1's seam:
// when the shared Redis dies mid-flight, BOTH instances degrade to their
// process-local token buckets and keep serving instead of hard-denying.
func TestRateLimiter_SharedRedis_Outage_LocalFallback_S1(t *testing.T) {
	mr := miniredis.RunT(t)
	rs, closeRedis, err := store.NewRedisStoreFromURL("redis://"+mr.Addr(), func(o *redis.Options) {
		o.MaxRetries = -1
		o.DialTimeout = 50 * time.Millisecond
		o.ReadTimeout = 50 * time.Millisecond
		o.WriteTimeout = 50 * time.Millisecond
	})
	if err != nil {
		t.Fatal(err)
	}
	instanceA := newS1Router(t, rs, 100, 100)
	instanceB := newS1Router(t, rs, 100, 100)

	_ = instanceA("5.5.5.5") // one live request through the shared path

	mr.Close() // store outage

	for i := 0; i < 2; i++ {
		if got := instanceA("5.5.5.5"); got != http.StatusNoContent {
			t.Fatalf("instance A outage request %d: %d, want 204", i, got)
		}
		if got := instanceB("5.5.5.5"); got != http.StatusNoContent {
			t.Fatalf("instance B outage request %d: %d, want 204", i, got)
		}
	}
	_ = closeRedis()
}
