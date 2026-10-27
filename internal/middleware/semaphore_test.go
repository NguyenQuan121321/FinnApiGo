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
	var peak atomic.Int64
	started := make(chan struct{}, 11)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	var workers sync.WaitGroup
	t.Cleanup(func() {
		releaseAll()
		done := make(chan struct{})
		go func() {
			workers.Wait()
			close(done)
		}()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			t.Error("requests did not exit after releasing the handler barrier")
		}
	})

	handler := cl.Handler()
	r := gin.New()
	r.GET("/", handler, func(c *gin.Context) {
		n := running.Add(1)
		defer running.Add(-1)
		for {
			previous := peak.Load()
			if n <= previous || peak.CompareAndSwap(previous, n) {
				break
			}
		}
		started <- struct{}{}
		<-release
		c.Status(http.StatusOK)
	})

	request := func(results chan<- int) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			results <- w.Code
		}()
	}
	expectResponses := func(results <-chan int, count, want int) {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for i := 0; i < count; i++ {
			select {
			case code := <-results:
				if code != want {
					t.Fatalf("response=%d want=%d", code, want)
				}
			case <-timer.C:
				t.Fatalf("timed out waiting for response %d of %d", i+1, count)
			}
		}
	}

	// Keep exactly five requests admitted until the test explicitly releases
	// them. Total requests served over multiple waves is not peak concurrency.
	admitted := make(chan int, 5)
	for i := 0; i < 5; i++ {
		request(admitted)
	}
	func() {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for i := 0; i < 5; i++ {
			select {
			case <-started:
			case <-timer.C:
				t.Fatalf("timed out waiting for admitted request %d of 5", i+1)
			}
		}
	}()
	if running.Load() != 5 || cl.Available() != 0 {
		t.Fatalf("occupied: running=%d available=%d want=5,0", running.Load(), cl.Available())
	}

	excess := make(chan int, 5)
	for i := 0; i < 5; i++ {
		request(excess)
	}
	expectResponses(excess, 5, http.StatusTooManyRequests)
	if running.Load() != 5 || peak.Load() != 5 || cl.Available() != 0 {
		t.Fatalf("excess requests changed occupancy: running=%d peak=%d available=%d", running.Load(), peak.Load(), cl.Available())
	}

	releaseAll()
	expectResponses(admitted, 5, http.StatusOK)
	if running.Load() != 0 || cl.Available() != 5 {
		t.Fatalf("released: running=%d available=%d want=0,5", running.Load(), cl.Available())
	}

	later := make(chan int, 1)
	request(later)
	expectResponses(later, 1, http.StatusOK)
	if running.Load() != 0 || peak.Load() != 5 || cl.Available() != 5 {
		t.Fatalf("reuse: running=%d peak=%d available=%d want=0,5,5", running.Load(), peak.Load(), cl.Available())
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
