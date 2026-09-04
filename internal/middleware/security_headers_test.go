package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func setupHeadersRouter(hsts int) (*gin.Engine, *httptest.ResponseRecorder, *http.Request) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeaders(hsts))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil)
}

// TestSecurityHeaders_BaselineHeaders — CSP (V8), nosniff, no-referrer and
// no-store are present on EVERY response.
func TestSecurityHeaders_BaselineHeaders(t *testing.T) {
	r, w, req := setupHeadersRouter(0)
	r.ServeHTTP(w, req)
	h := w.Header()
	for header, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
	} {
		if got := h.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if _, ok := h["Strict-Transport-Security"]; ok {
		t.Error("HSTS header must be absent on plain-HTTP requests")
	}
}

// TestSecurityHeaders_HSTS_OnForwardedTLS — the trusted X-Forwarded-Proto
// path enables HSTS when configured.
func TestSecurityHeaders_HSTS_OnForwardedTLS(t *testing.T) {
	r, w, req := setupHeadersRouter(31536000)
	req.Header.Set("X-Forwarded-Proto", "https")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("HSTS = %q, want max-age=31536000", got)
	}
}

// TestSecurityHeaders_HSTS_DirectTLS — the request.TLS path (a direct TLS
// connection, not a proxy hint).
func TestSecurityHeaders_HSTS_DirectTLS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeaders(600))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.TLS = &tls.ConnectionState{} // server-side view: connection was TLS
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=600" {
		t.Fatalf("HSTS = %q, want max-age=600", got)
	}
}

func TestHasRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if HasRole(c, "admin") {
		t.Fatal("no role set — HasRole must be false")
	}
	c.Set(CtxRole, "admin")
	if !HasRole(c, "admin") {
		t.Fatal("role=admin set — HasRole(admin) must be true")
	}
	if HasRole(c, "user") {
		t.Fatal("HasRole(user) for role=admin must be false")
	}
	c.Set(CtxRole, 42) // wrong type — must degrade to false, not panic
	if HasRole(c, "admin") {
		t.Fatal("non-string role must read as false")
	}
}

// TestRateLimiter_SweepEvictsStaleEntries — sweep() drops entries untouched
// for longer than entryTTL, keeping the visitor map bounded.
func TestRateLimiter_SweepEvictsStaleEntries(t *testing.T) {
	rl := NewRateLimiter(100, 100, time.Hour) // entryTTL 1h; sweeper runs but we call sweep directly
	defer rl.Close()
	_ = rl.get("1.2.3.4")
	_ = rl.get("5.6.7.8")
	// Age both entries past the TTL.
	rl.mu.Lock()
	for _, v := range rl.visitors {
		v.lastSeen = time.Now().Add(-2 * time.Hour)
	}
	rl.mu.Unlock()
	rl.sweep()
	rl.mu.Lock()
	remaining := len(rl.visitors)
	rl.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("sweep left %d entries, want 0", remaining)
	}
}

// TestSemaphore_AvailableAndCapacity — trivial getters.
func TestSemaphore_AvailableAndCapacity(t *testing.T) {
	sem := NewConcurrencyLimiter(2)
	if sem.Capacity() != 2 {
		t.Fatalf("Capacity = %d, want 2", sem.Capacity())
	}
	if sem.Available() != 2 {
		t.Fatalf("Available = %d, want 2", sem.Available())
	}
}
