package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/store"
)

type testCounterStore struct{ count int64 }

func (s *testCounterStore) IncrBy(string, int64, time.Duration) int64 { s.count++; return s.count }

func TestRateLimiterSharedCounter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &testCounterStore{}
	rl := NewRateLimiter(1, 2, time.Minute, store)
	defer rl.Close()
	r := gin.New()
	r.Use(rl.Handler())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		want := http.StatusNoContent
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("request %d: status=%d want=%d", i, w.Code, want)
		}
	}
}

// TestRateLimiterSharedCounter_WindowResets_C4 — C4 end-to-end regression:
// after a client exceeds the burst and keeps hammering (all denied), the
// window still elapses one TTL after the FIRST increment and legitimate
// traffic flows again. Uses the REAL InMemoryStore with an injected clock, so
// the store semantics under test are the production ones.
func TestRateLimiterSharedCounter_WindowResets_C4(t *testing.T) {
	gin.SetMode(gin.TestMode)
	clock := time.Now()
	kv := store.NewInMemoryStore(0, store.WithClock(func() time.Time { return clock }))
	defer kv.Close()

	// rps=0.05 with burst=2 makes the shared-counter window burst/rps = 40s.
	rl := NewRateLimiter(0.05, 2, time.Minute, kv)
	defer rl.Close()
	r := gin.New()
	r.Use(rl.Handler())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	do := func() int {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w.Code
	}

	if got := do(); got != http.StatusNoContent {
		t.Fatalf("request 1: %d", got)
	}
	if got := do(); got != http.StatusNoContent {
		t.Fatalf("request 2: %d", got)
	}
	if got := do(); got != http.StatusTooManyRequests {
		t.Fatalf("request 3 (over burst): %d", got)
	}
	// Keep hammering well past the burst — every hit is denied, and each one
	// lands INSIDE the original window (so a TTL refreshed by these hits
	// would outlive it).
	clock = clock.Add(30 * time.Second)
	for i := 0; i < 5; i++ {
		if got := do(); got != http.StatusTooManyRequests {
			t.Fatalf("hammer %d: %d", i, got)
		}
	}
	// Past the 40s window anchored at the FIRST increment the counter must
	// have reset even though denied requests kept arriving at t=30s.
	clock = clock.Add(11 * time.Second)
	if got := do(); got != http.StatusNoContent {
		t.Fatalf("after window: status=%d, want 204 (counter must reset)", got)
	}
}

// brokenCounterStore simulates a store whose backend is DOWN: counters fail
// open (IncrBy → 0, the A1 contract) and nothing is knowable.
type brokenCounterStore struct{}

func (brokenCounterStore) IncrBy(string, int64, time.Duration) int64 { return 0 }

// TestRateLimiter_StoreOutage_StillServes_A1 — A1 end-to-end: when the shared
// store is failing, rate-limited routes must still serve (fail open, falling
// back to the process-local token bucket) instead of hard-denying traffic.
func TestRateLimiter_StoreOutage_StillServes_A1(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := NewRateLimiter(100, 100, time.Minute, brokenCounterStore{})
	defer rl.Close()
	r := gin.New()
	r.Use(rl.Handler())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusNoContent {
			t.Fatalf("request %d during store outage: status=%d, want 204", i, w.Code)
		}
	}
}
