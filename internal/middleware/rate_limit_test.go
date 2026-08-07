package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
