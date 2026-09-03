package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/routes"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestLiveAPIDemo executes live HTTP calls against the Gin router and asserts real responses.
func TestLiveAPIDemo(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 1. Setup in-memory DB
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	_ = db.AutoMigrate(
		&models.Tenant{},
		&models.User{},
		&models.RefreshToken{},
		&models.Session{},
		&models.AuditLog{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
		&models.PasskeyCredential{},
		&models.OAuthIdentity{},
		&models.Permission{},
		&models.Role{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.TrustedDevice{},
		&models.WebhookEndpoint{},
		&models.WebhookDelivery{},
	)

	// Seed default tenant and permissions
	db.Create(&models.Tenant{ID: "default", Slug: "default", Name: "Default Organization", IsActive: true})
	permUsersRead := models.Permission{Name: "users:read", Description: "Read user list"}
	permUsersWrite := models.Permission{Name: "users:write", Description: "Manage users"}
	db.Create(&permUsersRead)
	db.Create(&permUsersWrite)

	// 2. Wire Repositories
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	rbacRepo := repositories.NewRBACRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	trustedDeviceRepo := repositories.NewTrustedDeviceRepository(db)
	webhookRepo := repositories.NewWebhookRepository(db)

	jwtSecret := "super-secure-enterprise-secret-key-32-chars!!"
	jwtMgr := jwt.NewJWTManager(jwtSecret, "finnapigo-test")
	kvStore := store.NewInMemoryStore(time.Minute)
	enc, _ := crypto.NewEncryptor([]byte("01234567890123456789012345678901"))

	authCfg := config.AuthConfig{
		MaxLoginAttempts:     5,
		LoginLockoutDuration: 15 * time.Minute,
		TOTPMaxAttempts:      5,
		TOTPAttemptWindow:    5 * time.Minute,
		RecoveryCodeCount:    5,
		RecoveryCodeBytes:    16,
	}

	totpSvc := services.NewTOTPService(
		totpRepo, kvStore, auditRepo, "FinnApiGo", authCfg, enc, jwtMgr,
		services.WithTOTPUserRepo(userRepo),
		services.WithTOTPPasskeys(passkeyRepo),
	)

	authSvc := services.NewAuthService(
		userRepo, tokenRepo, nil, auditRepo, kvStore,
		jwtMgr, authCfg, config.RateLimitConfig{}, config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour},
		nil, nil, nil, totpRepo, totpSvc,
		services.WithAuthPasskeys(passkeyRepo),
		services.WithAuthOAuthIdents(oauthRepo),
		services.WithSessionRepo(sessionRepo),
	)

	adminSvc := services.NewAdminService(userRepo, sessionRepo, tokenRepo, auditRepo, kvStore)
	trustedDeviceSvc := services.NewTrustedDeviceService(trustedDeviceRepo)
	webhookSvc := services.NewWebhookService(webhookRepo)

	authHandler := handlers.NewAuthHandler(authSvc, nil)
	mfaHandler := handlers.NewMFAHandler(totpSvc, nil, 15*time.Minute)
	sessionHandler := handlers.NewSessionHandler(authSvc)
	adminHandler := handlers.NewAdminHandler(adminSvc)
	trustedDeviceHandler := handlers.NewTrustedDeviceHandler(trustedDeviceSvc)
	webhookHandler := handlers.NewWebhookHandler(webhookSvc)

	deps := routes.Deps{
		Auth:                authHandler,
		MFA:                 mfaHandler,
		Sessions:            sessionHandler,
		Admin:               adminHandler,
		TrustedDevice:       trustedDeviceHandler,
		Webhook:             webhookHandler,
		RateLimit:           middleware.NewRateLimiter(100, 200, time.Minute),
		MaxRequestBodyBytes: 1 << 20,
		JWT:                 jwtMgr,
		Store:               kvStore,
		SwaggerEnabled:      true,
		RBACChecker:         rbacRepo,
	}
	router := routes.Register(deps)

	call := func(method, path string, body any, token string) (int, string) {
		var reqBody []byte
		if body != nil {
			reqBody, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, path, bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	fmt.Println("\n=================== LIVE HTTP API DEMONSTRATION ===================")

	// Call 1: GET /healthz
	code, resp := call(http.MethodGet, "/healthz", nil, "")
	fmt.Printf("[1] GET /healthz\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	// Call 2: POST /api/v1/auth/register (Weak password failure)
	weakRegister := map[string]any{
		"username": "tester",
		"email":    "tester@example.com",
		"password": "123", // too weak
		"fullName": "Test User",
	}
	code, resp = call(http.MethodPost, "/api/v1/auth/register", weakRegister, "")
	fmt.Printf("[2] POST /api/v1/auth/register (Weak Password -> Error Validation)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak password, got %d", code)
	}

	// Call 3: POST /api/v1/auth/register (Valid registration)
	validRegister := map[string]any{
		"username": "tester",
		"email":    "tester@example.com",
		"password": "Tr0ngM@tKhau#2026_Secure!",
		"fullName": "Enterprise Tester",
	}
	code, resp = call(http.MethodPost, "/api/v1/auth/register", validRegister, "")
	fmt.Printf("[3] POST /api/v1/auth/register (Valid Registration -> Success)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusCreated {
		t.Fatalf("expected 201 for register, got %d", code)
	}

	// Call 4: POST /api/v1/auth/login (Wrong password -> 401)
	wrongLogin := map[string]any{
		"email":    "tester@example.com",
		"password": "WrongPassword#999!",
	}
	code, resp = call(http.MethodPost, "/api/v1/auth/login", wrongLogin, "")
	fmt.Printf("[4] POST /api/v1/auth/login (Wrong Password -> Error 401)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong credentials, got %d", code)
	}

	// Call 5: POST /api/v1/auth/login (Correct password -> 200 OK with tokens)
	correctLogin := map[string]any{
		"email":    "tester@example.com",
		"password": "Tr0ngM@tKhau#2026_Secure!",
	}
	code, resp = call(http.MethodPost, "/api/v1/auth/login", correctLogin, "")
	fmt.Printf("[5] POST /api/v1/auth/login (Correct Credentials -> Success with Tokens)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for login, got %d", code)
	}

	// Extract access token
	var loginEnvelope struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(resp), &loginEnvelope)
	userToken := loginEnvelope.Data.AccessToken
	if userToken == "" {
		t.Fatal("expected non-empty access token")
	}

	// Call 6: GET /api/v1/auth/me (Authenticated profile call)
	code, resp = call(http.MethodGet, "/api/v1/auth/me", nil, userToken)
	fmt.Printf("[6] GET /api/v1/auth/me (Bearer Token -> User Profile)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for /me, got %d", code)
	}

	// Call 7: GET /api/v1/admin/users (Non-admin token -> 403 Forbidden)
	code, resp = call(http.MethodGet, "/api/v1/admin/users", nil, userToken)
	fmt.Printf("[7] GET /api/v1/admin/users (Regular User Token -> Error 403 Forbidden)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for regular user on admin endpoint, got %d", code)
	}

	// Create admin token for privileged calls
	adminToken, _ := jwtMgr.IssueAccessEnterprise(999, "admin", "admin@example.com", time.Hour, 1, "sess-admin", "default", []string{"users:read", "users:write", "webhooks:write"})

	// Call 8: GET /api/v1/admin/users (Admin token -> 200 OK list)
	code, resp = call(http.MethodGet, "/api/v1/admin/users", nil, adminToken)
	fmt.Printf("[8] GET /api/v1/admin/users (Admin Token -> Success Paginated Users)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for admin list users, got %d", code)
	}

	// Call 9: POST /api/v1/admin/webhooks (SSRF loopback protection -> 400 Bad Request)
	ssrfPayload := map[string]any{
		"url":    "http://127.0.0.1:8080/internal/secret",
		"events": "user.created",
	}
	code, resp = call(http.MethodPost, "/api/v1/admin/webhooks", ssrfPayload, adminToken)
	fmt.Printf("[9] POST /api/v1/admin/webhooks (SSRF Loopback Blocked -> Error 400)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for SSRF target, got %d", code)
	}

	// Call 10: POST /api/v1/admin/users/999/lock (Admin attempts to lock themselves -> 400 Bad Request)
	lockSelfPayload := map[string]any{
		"durationSeconds": 3600,
	}
	code, resp = call(http.MethodPost, "/api/v1/admin/users/999/lock", lockSelfPayload, adminToken)
	fmt.Printf("[10] POST /api/v1/admin/users/999/lock (Self-Lockout Prevention -> Error 400)\n    Status: %d\n    Body: %s\n\n", code, resp)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for self-lockout, got %d", code)
	}

	fmt.Println("===================================================================")
}
