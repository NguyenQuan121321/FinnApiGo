package routes

import (
	"bytes"
	"context"
	"crypto/tls"

	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/metrics"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/services"
)

func TestRegisterSmokeAndLogRedaction(t *testing.T) {
	// Capture the default slog handler's output so the redaction assertion
	// below actually inspects what requestLogger emitted.
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	router := Register(Deps{
		Auth: handlers.NewAuthHandler(nil, nil), MFA: handlers.NewMFAHandler(nil, nil, 0),
		JWT: jwt.NewJWTManager("test-secret", "test"), RateLimit: middleware.NewRateLimiter(100, 100, time.Minute),
	})
	for _, tc := range []struct {
		path string
		want int
	}{{"/healthz", 200}, {"/missing", 404}} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s: status=%d", tc.path, w.Code)
		}
	}
	secret := "Bearer super-secret-token"
	password := "correct-horse-battery-staple"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"a@example.com","password":"`+password+`"}`))
	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), req)
	logged, err := io.ReadAll(&logs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), secret) || strings.Contains(string(logged), password) {
		t.Fatalf("sensitive value leaked into logs: %s", logged)
	}
}

// TestSessionRoutes verifies the session-management endpoints are wired with
// AuthMiddleware: unauthenticated calls are rejected, authenticated calls reach
// the handler, and a valid JWT path param flows through.
func TestSessionRoutes(t *testing.T) {
	uid := uint(7)
	svc := &stubSessionService{}
	router := Register(Deps{
		Auth: handlers.NewAuthHandler(nil, nil), MFA: handlers.NewMFAHandler(nil, nil, 0),
		Sessions:  handlers.NewSessionHandler(svc),
		JWT:       jwt.NewJWTManager("test-secret", "test"),
		RateLimit: middleware.NewRateLimiter(100, 100, time.Minute),
	})

	// Unauthenticated GET /sessions → 401 via AuthMiddleware.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list: status=%d body=%s", w.Code, w.Body.String())
	}

	// Unauthenticated DELETE /sessions/:id → 401 via AuthMiddleware.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/3", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated revoke: status=%d body=%s", w.Code, w.Body.String())
	}

	// Authenticated requests reach the handler.
	token := issueTestToken(t, uid)
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated list: status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"sessions"`) {
		t.Fatalf("expected sessions payload: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated revoke: status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.revokedID != 3 || svc.revokeUserID != uid {
		t.Fatalf("revoke got (%d for user %d), want (3 for user %d)", svc.revokedID, svc.revokeUserID, uid)
	}
}

// TestSessionRoutes_TrustedProxyIP verifies that X-Forwarded-For is honored
// only when the direct peer is a trusted proxy: with TRUSTED_PROXIES unset,
// a client-spoofed XFF must NOT change the resolved client IP.
func TestSessionRoutes_TrustedProxyIP(t *testing.T) {
	svc := &stubSessionService{}
	router := Register(Deps{
		Auth: handlers.NewAuthHandler(nil, nil), MFA: handlers.NewMFAHandler(nil, nil, 0),
		Sessions:  handlers.NewSessionHandler(svc),
		JWT:       jwt.NewJWTManager("test-secret", "test"),
		RateLimit: middleware.NewRateLimiter(100, 100, time.Minute),
		// TrustedProxies intentionally empty → trust no proxy headers.
	})
	token := issueTestToken(t, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Attacker-supplied spoofed chain.
	req.Header.Set("X-Forwarded-For", "1.3.3.7, 9.9.9.9")
	req.Header.Set("X-Real-IP", "1.3.3.7")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// With no trusted proxies, the recorded IP must NOT be the spoofed one.
	if svc.lastIP == "1.3.3.7" {
		t.Fatalf("spoofed X-Forwarded-For leaked into client IP: %q", svc.lastIP)
	}
}

// stubSessionService records calls for assertions.
type stubSessionService struct {
	lastIP       string
	revokedID    uint
	revokeUserID uint
}

func (s *stubSessionService) ListSessions(_ context.Context, userID uint) ([]services.SessionInfo, error) {
	// Return one row so the JSON envelope is meaningful.
	return []services.SessionInfo{{ID: 1, DeviceName: "Chrome on Windows"}}, nil
}

func (s *stubSessionService) RevokeSession(_ context.Context, id, userID uint, ip string) error {
	s.revokedID, s.revokeUserID, s.lastIP = id, userID, ip
	return nil
}

// issueTestToken mints a valid access JWT for the given user id.
func issueTestToken(t *testing.T, uid uint) string {
	t.Helper()
	tok, err := jwt.NewJWTManager("test-secret", "test").Issue(uid, "user", "u@example.com", jwt.TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestRoutes_TokenEndpointsRateLimited_A5 — A5 regression: the public
// token-consumption endpoints (/refresh-token, /reset-password,
// /verify-email) must sit behind the rate limiter. With burst=1 the second
// immediate request must 429 before reaching the (nil-service) handler.
func TestRoutes_TokenEndpointsRateLimited_A5(t *testing.T) {
	for _, path := range []string{"/api/v1/auth/refresh-token", "/api/v1/auth/reset-password", "/api/v1/auth/verify-email"} {
		t.Run(path, func(t *testing.T) {
			router := Register(Deps{
				Auth: handlers.NewAuthHandler(nil, nil), MFA: handlers.NewMFAHandler(nil, nil, 0),
				JWT:       jwt.NewJWTManager("test-secret", "test"),
				RateLimit: middleware.NewRateLimiter(100, 1, time.Minute),
			})
			hit := func() int {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
				return w.Code
			}
			first := hit()
			if first == http.StatusTooManyRequests {
				t.Fatalf("first request must not be rate limited, got %d", first)
			}
			if second := hit(); second != http.StatusTooManyRequests {
				t.Fatalf("second request within burst=1 window must 429, got %d", second)
			}
		})
	}
}

// TestRoutes_SecurityHeadersOnTokenBearingResponse_A3 — A3: responses from
// the auth API must carry X-Content-Type-Options: nosniff and
// Cache-Control: no-store (HSTS additionally on HTTPS requests when
// configured). Asserted on /login, which mints tokens.
func TestRoutes_SecurityHeadersOnTokenBearingResponse_A3(t *testing.T) {
	router := Register(Deps{
		Auth: handlers.NewAuthHandler(nil, nil), MFA: handlers.NewMFAHandler(nil, nil, 0),
		JWT:         jwt.NewJWTManager("test-secret", "test"),
		RateLimit:   middleware.NewRateLimiter(100, 100, time.Minute),
		HSTSSeconds: 31536000,
	})

	// Plain-HTTP request: nosniff + no-store, but no HSTS.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"email":"a@example.com","password":"Password1"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS must not be sent over plain HTTP, got %q", got)
	}

	// HTTPS request (X-Forwarded-Proto from a trusted peer): HSTS appears.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"email":"a@example.com","password":"Password1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.TLS = &tls.ConnectionState{}
	router.ServeHTTP(w, req)
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("Strict-Transport-Security = %q, want max-age=31536000", got)
	}
}

// TestRoutes_MetricsAndHealthz_P2 — P2 gate: the Prometheus endpoint and the
// liveness probe both respond 200 in an httptest; /metrics is mounted only
// when a handler is provided.
func TestRoutes_MetricsAndHealthz_P2(t *testing.T) {
	build := func(withMetrics bool) *gin.Engine {
		deps := Deps{
			Auth: handlers.NewAuthHandler(nil, nil), MFA: handlers.NewMFAHandler(nil, nil, 0),
			JWT:       jwt.NewJWTManager("test-secret", "test"),
			RateLimit: middleware.NewRateLimiter(100, 100, time.Minute),
		}
		if withMetrics {
			deps.Metrics = metrics.Handler(nil)
		}
		return Register(deps)
	}

	router := build(true)
	for _, path := range []string{"/metrics", "/healthz"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d, want 200", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{
		"finnapigo_store_errors_total",
		"finnapigo_audit_entries_dropped_total",
		"finnapigo_rate_limited_requests_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %s", want)
		}
	}

	// Without a handler wired the endpoint is absent (404), not a panic.
	if w := httptest.NewRecorder(); func() int {
		router2 := build(false)
		router2.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return w.Code
	}() != http.StatusNotFound {
		t.Errorf("nil Metrics must leave /metrics unmounted, got %d", w.Code)
	}
}
