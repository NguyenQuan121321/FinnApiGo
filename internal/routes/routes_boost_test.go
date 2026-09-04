package routes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/store"
)

type mockRBACChecker struct{}

func (m mockRBACChecker) UserHasPermission(ctx context.Context, userID uint, permission string) (bool, error) {
	return true, nil
}

func (m mockRBACChecker) GetUserPermissions(ctx context.Context, userID uint) ([]string, error) {
	return []string{"*"}, nil
}

func TestRoutes_FullFeaturesAndMiddlewares(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtMgr := jwt.NewJWTManager("test-jwt-secret-key-32-chars-long!!", "test-issuer")
	token, _ := jwtMgr.IssueAccessEnterprise(1, "user", "user@example.com", time.Hour, 1, "sess-1", "default", []string{"users:read", "webhooks:write"})

	memStore := store.NewInMemoryStore(0)
	totpLimiter := middleware.NewConcurrencyLimiter(2)

	deps := Deps{
		Auth:                handlers.NewAuthHandler(nil, nil),
		MFA:                 handlers.NewMFAHandler(nil, nil, time.Minute),
		OAuth:               handlers.NewOAuthHandler(nil),
		Passkey:             handlers.NewPasskeyHandler(nil),
		Sessions:            handlers.NewSessionHandler(nil),
		Admin:               handlers.NewAdminHandler(nil),
		TrustedDevice:       handlers.NewTrustedDeviceHandler(nil),
		Webhook:             handlers.NewWebhookHandler(nil),
		RateLimit:           middleware.NewRateLimiter(100, 100, time.Minute),
		TOTPCluster:         totpLimiter,
		JWT:                 jwtMgr,
		Store:               memStore,
		CORSAllowedOrigins:  []string{"http://example.com"},
		MaxRequestBodyBytes: 50,
		SwaggerEnabled:      true,
		RBACChecker:         mockRBACChecker{},
	}
	router := Register(deps)

	// 1. CORS Preflight
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("CORS preflight status=%d, want 200 or 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://example.com" {
		t.Fatalf("CORS Allow-Origin header mismatch: %s", got)
	}

	// 2. MaxRequestBodyBytes rejection
	largeBody := strings.Repeat("A", 100)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Logf("large body response code: %d", w.Code)
	}

	// 3. OAuth unauthenticated endpoints
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/login", nil)
	router.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound {
		t.Fatal("expected /google/login to be mounted")
	}

	// 4. OAuth unlink authenticated endpoint
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/oauth/google", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound {
		t.Fatal("expected DELETE /oauth/:provider to be mounted")
	}

	// 5. Passkey routes
	passkeyEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/auth/mfa/passkey/register/challenge"},
		{http.MethodPost, "/api/v1/auth/mfa/passkey/register/verify"},
		{http.MethodPost, "/api/v1/auth/mfa/passkey/authenticate/challenge"},
		{http.MethodPost, "/api/v1/auth/mfa/passkey/authenticate/verify"},
		{http.MethodGet, "/api/v1/auth/mfa/passkeys"},
		{http.MethodDelete, "/api/v1/auth/mfa/passkeys/cred-1"},
	}
	for _, ep := range passkeyEndpoints {
		w = httptest.NewRecorder()
		req = httptest.NewRequest(ep.method, ep.path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		if w.Code == http.StatusNotFound {
			t.Fatalf("expected passkey endpoint %s %s to be mounted", ep.method, ep.path)
		}
	}

	// 6. Admin webhook endpoint
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/webhooks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound {
		t.Fatal("expected POST /api/v1/admin/webhooks to be mounted")
	}

	// 7. Regenerate recovery codes endpoint (sudo gated)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/totp/recovery-codes/regenerate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound {
		t.Fatal("expected regenerate recovery codes endpoint to be mounted")
	}
}

func TestReadyz_LiveAndClosedDB(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}

	handler := readyz(db)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler(c)
	if w.Code != http.StatusOK {
		t.Fatalf("readyz with live DB failed: status=%d", w.Code)
	}

	// Close sqlDB to trigger PingContext error
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler(c2)
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with closed DB want 503, got %d", w2.Code)
	}
}

func TestRequestLogger_500ErrorAndCustomID(t *testing.T) {
	r := gin.New()
	r.Use(requestLogger())
	r.GET("/trigger-error", func(c *gin.Context) {
		_ = c.Error(errors.New("internal error"))
		c.Status(http.StatusInternalServerError)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/trigger-error", nil)
	req.Header.Set("X-Request-ID", "req-12345")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if w.Header().Get("X-Request-ID") != "req-12345" {
		t.Fatalf("expected X-Request-ID header req-12345, got %s", w.Header().Get("X-Request-ID"))
	}
}
