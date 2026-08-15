package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
)

// Each test chains AuthMiddleware → SudoMiddleware exactly like the real
// routes: access token in Authorization, sudo token in X-Sudo-Token.
func TestSudoMiddleware_AcceptsValidSudoToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	access, _ := jwtMgr.Issue(42, "user", "alice@example.com", jwt.TokenTypeAccess, 15*time.Minute)
	sudo, _ := jwtMgr.Issue(42, "user", "alice@example.com", jwt.TokenTypeSudo, 15*time.Minute)

	r := gin.New()
	r.POST("/sensitive", AuthMiddleware(jwtMgr), SudoMiddleware(jwtMgr), func(c *gin.Context) {
		until := SudoUntil(c)
		if until.IsZero() {
			t.Error("SudoUntil should be set for a token with expiry")
		}
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set(SudoHeader, sudo)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestSudoMiddleware_RejectsMissingHeader(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	access, _ := jwtMgr.Issue(42, "user", "", jwt.TokenTypeAccess, 15*time.Minute)

	r := gin.New()
	r.POST("/sensitive", AuthMiddleware(jwtMgr), SudoMiddleware(jwtMgr), func(c *gin.Context) {
		t.Error("handler should not be reached without sudo token")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestSudoMiddleware_RejectsAccessTokenAsSudo(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	access, _ := jwtMgr.Issue(42, "user", "", jwt.TokenTypeAccess, 15*time.Minute)

	r := gin.New()
	r.POST("/sensitive", AuthMiddleware(jwtMgr), SudoMiddleware(jwtMgr), func(c *gin.Context) {
		t.Error("an access token must never satisfy sudo")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set(SudoHeader, access)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestSudoMiddleware_RejectsUserMismatch(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	// Session belongs to user 42, sudo token was minted for user 7.
	access, _ := jwtMgr.Issue(42, "user", "", jwt.TokenTypeAccess, 15*time.Minute)
	foreignSudo, _ := jwtMgr.Issue(7, "user", "", jwt.TokenTypeSudo, 15*time.Minute)

	r := gin.New()
	r.POST("/sensitive", AuthMiddleware(jwtMgr), SudoMiddleware(jwtMgr), func(c *gin.Context) {
		t.Error("sudo token of another user must not elevate this session")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set(SudoHeader, foreignSudo)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestSudoMiddleware_RejectsExpiredSudoToken(t *testing.T) {
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	access, _ := jwtMgr.Issue(42, "user", "", jwt.TokenTypeAccess, 15*time.Minute)
	sudo, _ := jwtMgr.Issue(42, "user", "", jwt.TokenTypeSudo, -1*time.Minute)

	r := gin.New()
	r.POST("/sensitive", AuthMiddleware(jwtMgr), SudoMiddleware(jwtMgr), func(c *gin.Context) {
		t.Error("expired sudo token must be rejected")
		c.JSON(200, nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set(SudoHeader, sudo)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("status = %d, want 403", w.Code)
	}
}
