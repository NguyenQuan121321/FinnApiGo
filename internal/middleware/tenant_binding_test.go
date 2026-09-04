package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// TestAuthMiddleware_TenantClaimOverridesHeader — the P2.1 isolation gate:
// for an authenticated request, the tenant bound into the signed token ("tid")
// is the effective tenant, regardless of any X-Tenant-ID header the client
// sends. A spoofed header must never reach tenant-scoped queries.
func TestAuthMiddleware_TenantClaimOverridesHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mgr := jwt.NewJWTManager("test-secret-tenant-binding", "iss")
	// Token minted for tenant "acme" — as issueTokenPair now does via
	// IssueAccessEnterprise.
	tok, err := mgr.IssueAccessEnterprise(7, "user", "u@acme.io", time.Minute, 0, "sid-1", "acme", nil)
	if err != nil {
		t.Fatal(err)
	}

	captured := ""
	r := gin.New()
	r.Use(TenantMiddleware())
	r.Use(AuthMiddleware(mgr, nil))
	r.GET("/probe", func(c *gin.Context) {
		captured = tenant.FromContext(c.Request.Context())
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	// The spoof: authenticated as an acme user, but claiming tenant "other".
	req.Header.Set("X-Tenant-ID", "other-corp")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if captured != "acme" {
		t.Fatalf("effective tenant = %q, want the signed tid %q (header spoof must not win)", captured, "acme")
	}
}

// TestAuthMiddleware_NoTidClaim_HeaderStands — tokens minted before the tid
// claim (legacy AccessTTL window) carry no tenant; the header-derived value
// remains effective so those requests keep working until expiry.
func TestAuthMiddleware_NoTidClaim_HeaderStands(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mgr := jwt.NewJWTManager("test-secret-tenant-binding", "iss")
	tok, err := mgr.IssueAccess(7, "user", "u@acme.io", time.Minute, 0, "sid-legacy")
	if err != nil {
		t.Fatal(err)
	}

	captured := ""
	r := gin.New()
	r.Use(TenantMiddleware())
	r.Use(AuthMiddleware(mgr, nil))
	r.GET("/probe", func(c *gin.Context) {
		captured = tenant.FromContext(c.Request.Context())
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Tenant-ID", "legacy-co")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if captured != "legacy-co" {
		t.Fatalf("effective tenant = %q, want header value for a tid-less legacy token", captured)
	}
}

// TestAuthMiddleware_PermissionsClaimExposed — perms from the signed token
// land in the context for RequirePermission's fast path.
func TestAuthMiddleware_PermissionsClaimExposed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mgr := jwt.NewJWTManager("test-secret-tenant-binding", "iss")
	tok, err := mgr.IssueAccessEnterprise(9, "user", "u@e.io", time.Minute, 0, "sid-2", "default", []string{"users:read"})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	r := gin.New()
	r.Use(AuthMiddleware(mgr, nil))
	r.GET("/probe", func(c *gin.Context) {
		v, ok := c.Get(CtxPermissions)
		if ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(w, req)

	if len(got) != 1 || got[0] != "users:read" {
		t.Fatalf("permissions in ctx = %v, want [users:read]", got)
	}
}

// TestAuthMiddleware_DenylistSIDAndJTI — both denylist key families abort
// with 401 (P0.2/P0.3 enforcement point).
func TestAuthMiddleware_DenylistSIDAndJTI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mgr := jwt.NewJWTManager("test-secret-tenant-binding", "iss")
	st := store.NewInMemoryStore(0)

	r := gin.New()
	r.Use(AuthMiddleware(mgr, nil, WithDenylist(st)))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })

	// jti denylist: replaying the exact denylisted access token must 401.
	tok := mustAccess(t, mgr)
	claims, err := mgr.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	st.Set("denylist:jti:"+claims.ID, "revoked", time.Minute)
	if w := replay(r, tok); w.Code != http.StatusUnauthorized {
		t.Fatalf("jti-denylisted token: status = %d, want 401", w.Code)
	}

	// sid denylist: a fresh (non-denylisted jti) token whose session family
	// was revoked must 401 too.
	tok2 := mustAccess(t, mgr)
	claims2, err := mgr.Verify(tok2)
	if err != nil {
		t.Fatal(err)
	}
	st.Set("denylist:sid:"+claims2.SID, "revoked", time.Minute)
	if w := replay(r, tok2); w.Code != http.StatusUnauthorized {
		t.Fatalf("sid-denylisted token: status = %d, want 401", w.Code)
	}
}

func replay(r *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func mustAccess(t *testing.T, mgr *jwt.JWTManager) string {
	t.Helper()
	tok, err := mgr.IssueAccess(11, "user", "u@e.io", time.Minute, 0, "sid-11")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
