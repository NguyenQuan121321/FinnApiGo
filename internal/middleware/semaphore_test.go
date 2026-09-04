package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func TestConcurrencyLimiter_PassthroughWhenDisabled(t *testing.T) {
	cl := NewConcurrencyLimiter(0) // disabled
	r := gin.New()
	r.GET("/", cl.Handler(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestConcurrencyLimiter_NilIsPassthrough(t *testing.T) {
	var cl *ConcurrencyLimiter // nil
	r := gin.New()
	r.GET("/", cl.Handler(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestConcurrencyLimiter_AllowsUpToCapacity(t *testing.T) {
	cl := NewConcurrencyLimiter(5)
	if cl.Capacity() != 5 {
		t.Fatalf("capacity=%d want=5", cl.Capacity())
	}
	if cl.Available() != 5 {
		t.Fatalf("available=%d want=5", cl.Available())
	}

	var running atomic.Int64
	var served atomic.Int64
	var rejected atomic.Int64

	handler := cl.Handler()
	r := gin.New()
	r.GET("/", handler, func(c *gin.Context) {
		n := running.Add(1)
		if n > 5 {
			t.Errorf("concurrency exceeded: %d > 5", n)
		}
		time.Sleep(2 * time.Millisecond) // hold the slot so concurrent reqs collide
		running.Add(-1)
		served.Add(1)
		c.Status(http.StatusOK)
	})

	// Fire 10 concurrent requests while the semaphore is full — since the
	// acquire is non-blocking, only up to 5 can run; the rest are rejected.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code == http.StatusTooManyRequests {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()

	total := served.Load() + rejected.Load()
	if total != 10 {
		t.Fatalf("total handled=%d want=10 (served=%d rejected=%d)", total, served.Load(), rejected.Load())
	}
	if served.Load() > 5 {
		t.Fatalf("served=%d should not exceed capacity 5", served.Load())
	}
}

func TestConcurrencyLimiter_RejectsExcessWith429(t *testing.T) {
	cl := NewConcurrencyLimiter(2)

	handler := cl.Handler()
	r := gin.New()

	started := make(chan struct{}, 2)
	unblock := make(chan struct{})

	r.GET("/", handler, func(c *gin.Context) {
		started <- struct{}{}
		<-unblock
		c.Status(http.StatusOK)
	})

	rejected := atomic.Int64{}
	var wg sync.WaitGroup

	// Start 2 requests to fill the semaphore.
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}

	// Wait until both requests have acquired tokens.
	<-started
	<-started

	// Now fire a request that should be rejected immediately.
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code == http.StatusTooManyRequests {
			rejected.Add(1)
		}
	}()

	// Brief pause to allow third request to be rejected, then unblock workers.
	time.Sleep(5 * time.Millisecond)
	close(unblock)

	wg.Wait()

	if rejected.Load() == 0 {
		t.Fatal("expected at least one request to be rejected with 429")
	}
}

func TestConcurrencyLimiter_AvailableAndCapacity(t *testing.T) {
	cl := NewConcurrencyLimiter(3)
	if cl.Available() != 3 {
		t.Fatalf("initial available=%d want=3", cl.Available())
	}
	if cl.Capacity() != 3 {
		t.Fatalf("capacity=%d want=3", cl.Capacity())
	}
}
