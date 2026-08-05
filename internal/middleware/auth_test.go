package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupAuthRouter(jwtMgr *jwt.JWTManager) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuthMiddleware(jwtMgr))
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
