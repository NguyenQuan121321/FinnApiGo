package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"context"
	"errors"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupAuthRouter(jwtMgr *jwt.JWTManager) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuthMiddleware(jwtMgr, nil))
	r.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get(CtxUserID)
		role, _ := c.Get(CtxRole)
		c.JSON(http.StatusOK, gin.H{
			"code":    200,
			"message": "success",
			"data": gin.H{
				"user_id": userID,
				"role":    role,
			},
		})
	})
	return r
}

func TestAuthMiddleware_AcceptsAccessToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("secret", "test-issuer")
	token, _ := jwtMgr.Issue(1, "user", "test@test.com", jwt.TokenTypeAccess, time.Hour)

	r := setupAuthRouter(jwtMgr)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_RejectsResetToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("secret", "test-issuer")
	token, _ := jwtMgr.Issue(1, "user", "test@test.com", jwt.TokenTypeReset, time.Hour)

	r := setupAuthRouter(jwtMgr)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	assert.Equal(t, "invalid token type", res["message"])
}

func TestAuthMiddleware_RejectsVerifyEmailToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("secret", "test-issuer")
	token, _ := jwtMgr.Issue(1, "user", "test@test.com", jwt.TokenTypeEmailVerify, time.Hour)

	r := setupAuthRouter(jwtMgr)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_RejectsMissingHeader(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("secret", "test-issuer")

	r := setupAuthRouter(jwtMgr)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_RejectsExpiredToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("secret", "test-issuer")
	token, _ := jwtMgr.Issue(1, "user", "test@test.com", jwt.TokenTypeAccess, -time.Hour)

	r := setupAuthRouter(jwtMgr)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func setupRoleRouter(roles ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Mock middleware to set role
	r.Use(func(c *gin.Context) {
		c.Set(CtxRole, "user")
		c.Next()
	})

	r.Use(RequireRole(roles...))
	r.GET("/admin", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 200, "message": "success", "data": nil})
	})
	return r
}

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	r := setupRoleRouter("user", "admin")
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_RejectsMismatchedRole(t *testing.T) {
	r := setupRoleRouter("admin")
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestAuthMiddleware_DenialsAreLogged_A4 — A4 regression: every 401 from
// AuthMiddleware must emit exactly one slog.Warn carrying the client IP and
// request id so denials are triageable.
func TestAuthMiddleware_DenialsAreLogged_A4(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("request_id", "rid-a4-test"); c.Next() })
	r.GET("/p", AuthMiddleware(jwtMgr, nil), func(c *gin.Context) { c.Status(200) })

	req := httptest.NewRequest(http.MethodGet, "/p", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	out := logs.String()
	if n := strings.Count(out, `level=WARN msg="auth denied"`); n != 1 {
		t.Fatalf("expected exactly one auth-denied warn, got %d in: %s", n, out)
	}
	if !strings.Contains(out, "client_ip=") {
		t.Error("denial log must carry client_ip")
	}
	if !strings.Contains(out, "rid=rid-a4-test") {
		t.Error("denial log must carry the request id")
	}
}

// TestAuthMiddleware_StalePwdVersionRejected_A7 — A7: an access token whose
// pwdver claim falls behind the live counter (the credential changed since
// issue) must be rejected; equal versions pass, and a version-source error
// fails OPEN (bounded by the access TTL, the documented worst case).
func TestAuthMiddleware_StalePwdVersionRejected_A7(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	stale, err := jwtMgr.IssueAccess(7, "user", "u@e.com", time.Minute, 0, "sess-7")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := jwtMgr.IssueAccess(7, "user", "u@e.com", time.Minute, 1, "sess-7")
	if err != nil {
		t.Fatal(err)
	}
	var live int64 = 1
	src := func(ctx context.Context, userID uint) (int64, error) { return live, nil }

	do := func(token string, ver VersionSource) int {
		r := gin.New()
		r.GET("/p", AuthMiddleware(jwtMgr, ver), func(c *gin.Context) { c.Status(200) })
		req := httptest.NewRequest(http.MethodGet, "/p", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	if got := do(stale, src); got != 401 {
		t.Errorf("stale pwdver token: status=%d, want 401", got)
	}
	if got := do(fresh, src); got != 200 {
		t.Errorf("current pwdver token: status=%d, want 200", got)
	}
	// Source failing → fail open (AccessTTL bound).
	failSrc := func(ctx context.Context, userID uint) (int64, error) { return 0, errors.New("db down") }
	if got := do(stale, failSrc); got != 200 {
		t.Errorf("version source error must fail open: status=%d, want 200", got)
	}
}

type mockDenylist struct {
	denied map[string]bool
}

func (m *mockDenylist) Get(key string) (any, bool) {
	if m.denied[key] {
		return "revoked", true
	}
	return nil, false
}

func TestAuthMiddleware_DenylistRejected_P02(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	token, err := jwtMgr.IssueAccess(7, "user", "u@e.com", time.Minute, 1, "session-abc")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwtMgr.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	dl := &mockDenylist{denied: make(map[string]bool)}
	r := gin.New()
	var seenJTI, seenSID string
	r.GET("/p", AuthMiddleware(jwtMgr, nil, WithDenylist(dl)), func(c *gin.Context) {
		seenJTI = c.GetString(CtxJTI)
		seenSID = c.GetString(CtxSID)
		c.Status(200)
	})

	do := func() int {
		req := httptest.NewRequest(http.MethodGet, "/p", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// 1. Clean token passes and context is populated
	if code := do(); code != 200 {
		t.Fatalf("clean token failed: %d", code)
	}
	if seenJTI != claims.ID || seenSID != "session-abc" {
		t.Errorf("context not populated: jti=%q (want %q), sid=%q (want session-abc)", seenJTI, claims.ID, seenSID)
	}

	// 2. JTI denylisted → 401
	dl.denied["denylist:jti:"+claims.ID] = true
	if code := do(); code != 401 {
		t.Fatalf("denylisted JTI must return 401, got %d", code)
	}
	delete(dl.denied, "denylist:jti:"+claims.ID)

	// 3. SID denylisted → 401
	dl.denied["denylist:sid:session-abc"] = true
	if code := do(); code != 401 {
		t.Fatalf("denylisted SID must return 401, got %d", code)
	}
}
