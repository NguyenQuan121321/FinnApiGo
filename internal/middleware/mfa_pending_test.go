package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
)

func TestMFAPendingMiddleware_AcceptsMFAPendingToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	tok, _ := jwtMgr.Issue(42, "", "", jwt.TokenTypeMFAPending, 5*time.Minute)

	r := gin.New()
	r.POST("/mfa/login-verify", MFAPendingMiddleware(jwtMgr), func(c *gin.Context) {
		uid, _ := c.Get(CtxUserID)
		if uid.(uint) != 42 {
			t.Errorf("user_id = %v, want 42", uid)
		}
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/mfa/login-verify", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMFAPendingMiddleware_RejectsAccessToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	tok, _ := jwtMgr.Issue(42, "user", "alice@example.com", jwt.TokenTypeAccess, 15*time.Minute)

	r := gin.New()
	r.POST("/mfa/login-verify", MFAPendingMiddleware(jwtMgr), func(c *gin.Context) {
		t.Error("handler should not be reached with access token")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/mfa/login-verify", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestMFAPendingMiddleware_RejectsMissingHeader(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")

	r := gin.New()
	r.POST("/mfa/login-verify", MFAPendingMiddleware(jwtMgr), func(c *gin.Context) {
		t.Error("handler should not be reached without auth header")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/mfa/login-verify", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestMFAPendingMiddleware_RejectsExpiredToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	// Issue a token that expires in -1 minute (already expired).
	tok, _ := jwtMgr.Issue(42, "", "", jwt.TokenTypeMFAPending, -1*time.Minute)

	r := gin.New()
	r.POST("/mfa/login-verify", MFAPendingMiddleware(jwtMgr), func(c *gin.Context) {
		t.Error("handler should not be reached with expired token")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/mfa/login-verify", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_RejectsMFAPendingToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	tok, _ := jwtMgr.Issue(42, "", "", jwt.TokenTypeMFAPending, 5*time.Minute)

	r := gin.New()
	r.GET("/me", AuthMiddleware(jwtMgr, nil), func(c *gin.Context) {
		t.Error("handler should not be reached with mfa_pending token")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401 for mfa_pending token on protected route", w.Code)
	}
}
