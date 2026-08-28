package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/metrics"
	"github.com/finnapigo/finnapigo/internal/middleware"
)

// buildExposureRouter wires the public router exactly as main.go does for the
// two X1 modes: metrics on the public router (legacy) or nil (internal).
func buildExposureRouter(t *testing.T, metricsPublic http.Handler) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	return Register(Deps{
		Auth:      handlers.NewAuthHandler(nil, nil),
		MFA:       handlers.NewMFAHandler(nil, nil, time.Minute),
		Sessions:  handlers.NewSessionHandler(nil),
		RateLimit: middleware.NewRateLimiter(100, 200, time.Minute),
		Metrics:   metricsPublic,
	})
}

// TestMetrics_UnreachableOnPublicListenerWhenInternal_X1 — the X1 phase gate:
// when METRICS_ADDR is configured, main.go passes Metrics=nil to the router
// and the public listener must NOT serve /metrics; the payload is reachable
// only on the dedicated internal listener.
func TestMetrics_UnreachableOnPublicListenerWhenInternal_X1(t *testing.T) {
	r := buildExposureRouter(t, nil) // METRICS_ADDR mode
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("X1: /metrics on public listener with METRICS_ADDR set → %d, want 404", w.Code)
	}
}

// TestMetrics_OnPublicListenerInLegacyMode_X1 — legacy/dev mode (METRICS_ADDR
// unset) keeps /metrics working on the public router.
func TestMetrics_OnPublicListenerInLegacyMode_X1(t *testing.T) {
	r := buildExposureRouter(t, metrics.Handler(nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("X1: /metrics legacy mode → %d, want 200", w.Code)
	}
}
