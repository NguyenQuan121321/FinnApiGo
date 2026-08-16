package routes

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/services"
)

func TestRegisterSmokeAndLogRedaction(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
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
