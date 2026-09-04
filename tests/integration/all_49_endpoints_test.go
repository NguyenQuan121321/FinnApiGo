package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/finnapigo/finnapigo/docs"
	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/hash"
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
	"gorm.io/gorm/logger"
)

type mockOAuthService struct{}

func (m mockOAuthService) BeginLogin(ctx context.Context) (string, string, error) {
	return "test-state-123", "https://accounts.google.com/o/oauth2/v2/auth?client_id=test", nil
}

func (m mockOAuthService) HandleCallback(ctx context.Context, code, state, ip, ua string) (services.TokenPair, services.UserProfile, *services.MFAPendingResult, error) {
	return services.TokenPair{AccessToken: "mock-access-token", RefreshToken: "mock-refresh-token"},
		services.UserProfile{ID: 1, Email: "oauth@example.com"},
		nil, nil
}

func (m mockOAuthService) Unlink(ctx context.Context, userID uint, provider, ip string) error {
	if provider == "google" {
		return nil
	}
	return services.ErrUserNotFound
}

// TestAll49Endpoints executes an exhaustive audit and end-to-end verification of all 49 endpoints.
func TestAll49Endpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 1. Initialize in-memory SQLite database
	db, err := gorm.Open(sqlite.Open("file:all_endpoints_test?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	err = db.AutoMigrate(
		&models.Tenant{},
		&models.User{},
		&models.RefreshToken{},
		&models.UsedToken{},
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
	if err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	// 2. Seed Tenant, Permissions, Roles, and Test Users
	db.Create(&models.Tenant{ID: "default", Slug: "default", Name: "Default Organization", IsActive: true})

	perms := []models.Permission{
		{Name: "users:read", Description: "Read user list"},
		{Name: "users:write", Description: "Manage users"},
		{Name: "sessions:read", Description: "Read active sessions"},
		{Name: "audit:export", Description: "Export security logs"},
		{Name: "webhooks:write", Description: "Manage webhooks"},
	}
	for i := range perms {
		db.Create(&perms[i])
	}

	adminRole := models.Role{TenantID: "default", Name: "admin", Description: "Admin role"}
	db.Create(&adminRole)
	for _, p := range perms {
		db.Create(&models.RolePermission{RoleID: adminRole.ID, PermissionID: p.ID})
	}

	// Seed Admin User (ID: 1) and Normal User (ID: 2)
	// #nosec G101 -- test dummy credentials
	rawPassword := "Enterprise" + "P@ssw0rd2026!"
	hashedPwd, err := hash.HashPassword(rawPassword)
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}

	enc, err := crypto.NewEncryptor([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	rbacRepo := repositories.NewRBACRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	trustedDeviceRepo := repositories.NewTrustedDeviceRepository(db)
	webhookRepo := repositories.NewWebhookRepository(db)

	adminUser := &models.User{
		TenantID: "default", Username: "admin_user", Email: "admin@enterprise.com",
		Password: hashedPwd, Role: "admin", IsActive: true, IsEmailVerified: true,
	}
	_ = userRepo.Create(context.Background(), adminUser)
	db.Create(&models.UserRole{UserID: adminUser.ID, RoleID: adminRole.ID})

	normalUser := &models.User{
		TenantID: "default", Username: "regular_user", Email: "user@enterprise.com",
		Password: hashedPwd, Role: "user", IsActive: true, IsEmailVerified: true,
	}
	_ = userRepo.Create(context.Background(), normalUser)

	// Seed active sessions
	db.Create(&models.Session{
		ID:           "sess-user",
		UserID:       normalUser.ID,
		TenantID:     "default",
		IPAddress:    "127.0.0.1",
		UserAgent:    "integration-test",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	})
	db.Create(&models.Session{
		ID:           "sess-user-secondary",
		UserID:       normalUser.ID,
		TenantID:     "default",
		IPAddress:    "127.0.0.1",
		UserAgent:    "integration-test",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	})
	db.Create(&models.Session{
		ID:           "sess-admin",
		UserID:       adminUser.ID,
		TenantID:     "default",
		IPAddress:  "127.0.0.1",
		UserAgent:  "integration-test",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		LastActiveAt: time.Now(),
	})

	// Seed trusted device
	db.Create(&models.TrustedDevice{
		ID:         1,
		UserID:     normalUser.ID,
		DeviceHash: "fp-test-123",
		DeviceName: "Test Laptop",
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
		CreatedAt:  time.Now(),
	})

	// Seed passkey credential
	db.Create(&models.PasskeyCredential{
		ID:           1,
		UserID:       normalUser.ID,
		CredentialID: []byte("passkey-cred-id-1"),
		PublicKey:    []byte("passkey-public-key-1"),
		DisplayName:  "Security Key",
		CreatedAt:    time.Now(),
	})

	// Seed OAuth Identity
	db.Create(&models.OAuthIdentity{
		UserID:         normalUser.ID,
		Provider:       "google",
		ProviderUserID: "google-uid-12345",
	})

	// 3. Initialize Services and Handlers
	// #nosec G101 -- test dummy key
	jwtSecret := "super-secure-enterprise" + "-key-32-chars-minimum!!"
	jwtMgr := jwt.NewJWTManager(jwtSecret, "finnapigo-test")
	kvStore := store.NewInMemoryStore(time.Minute)

	authCfg := config.AuthConfig{
		MaxLoginAttempts:     5,
		LoginLockoutDuration: 15 * time.Minute,
		TOTPMaxAttempts:      5,
		TOTPAttemptWindow:    5 * time.Minute,
		RecoveryCodeCount:    5,
		RecoveryCodeBytes:    16,
	}

	consoleNotifier := services.NewConsoleNotifier("noreply@finnapigo.local")

	totpSvc := services.NewTOTPService(
		totpRepo, kvStore, auditRepo, "FinnApiGo", authCfg, enc, jwtMgr,
		services.WithTOTPUserRepo(userRepo),
		services.WithTOTPPasskeys(passkeyRepo),
	)

	authSvc := services.NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, kvStore,
		jwtMgr, authCfg, config.RateLimitConfig{},
		config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour},
		consoleNotifier, nil, nil, totpRepo, totpSvc,
		services.WithAuthPasskeys(passkeyRepo),
		services.WithAuthOAuthIdents(oauthRepo),
		services.WithSessionRepo(sessionRepo),
	)

	passkeySvc, err := services.NewPasskeyService(passkeyRepo, userRepo, auditRepo, kvStore, authSvc, services.PasskeyConfig{
		RPDisplayName: "FinnApiGo Enterprise",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		t.Fatalf("failed to initialize passkey service: %v", err)
	}

	adminSvc := services.NewAdminService(userRepo, sessionRepo, tokenRepo, auditRepo, kvStore)
	trustedDeviceSvc := services.NewTrustedDeviceService(trustedDeviceRepo)
	webhookSvc := services.NewWebhookService(webhookRepo)

	authHandler := handlers.NewAuthHandler(authSvc, nil)
	oauthHandler := handlers.NewOAuthHandler(mockOAuthService{})
	mfaHandler := handlers.NewMFAHandler(totpSvc, jwtMgr, 15*time.Minute)
	sessionHandler := handlers.NewSessionHandler(authSvc)
	passkeyHandler := handlers.NewPasskeyHandler(passkeySvc)
	adminHandler := handlers.NewAdminHandler(adminSvc)
	trustedDeviceHandler := handlers.NewTrustedDeviceHandler(trustedDeviceSvc)
	webhookHandler := handlers.NewWebhookHandler(webhookSvc)

	// 4. Construct Router with All Dependencies
	deps := routes.Deps{
		Auth:                authHandler,
		OAuth:               oauthHandler,
		MFA:                 mfaHandler,
		Sessions:            sessionHandler,
		Passkey:             passkeyHandler,
		Admin:               adminHandler,
		TrustedDevice:       trustedDeviceHandler,
		Webhook:             webhookHandler,
		RateLimit:           middleware.NewRateLimiter(1000, 2000, time.Minute),
		TOTPCluster:         middleware.NewConcurrencyLimiter(5),
		JWT:                 jwtMgr,
		Store:               kvStore,
		DB:                  db,
		Metrics:             http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("# HELP metrics")) }),
		SwaggerEnabled:      true,
		MaxRequestBodyBytes: 1 << 20,
		RBACChecker:         rbacRepo,
	}
	router := routes.Register(deps)

	// 5. Assert Total Route Count
	routesList := router.Routes()
	t.Logf(">>> Total registered routes: %d", len(routesList))
	if len(routesList) < 48 {
		t.Fatalf("expected at least 48 routes, found %d", len(routesList))
	}

	// 6. Helpers for issuing tokens
	freshAdminToken := func() string {
		var u models.User
		_ = db.First(&u, adminUser.ID).Error
		tok, _ := jwtMgr.IssueAccessEnterprise(u.ID, "admin", u.Email, time.Hour, u.PwdVersion, "sess-admin", "default", []string{"users:read", "users:write", "sessions:read", "audit:export", "webhooks:write"})
		return tok
	}

	freshUserToken := func() string {
		var u models.User
		_ = db.First(&u, normalUser.ID).Error
		tok, _ := jwtMgr.IssueAccessEnterprise(u.ID, u.Role, u.Email, time.Hour, u.PwdVersion, "sess-user", "default", nil)
		return tok
	}

	mfaPendingToken, _ := jwtMgr.Issue(normalUser.ID, "user", normalUser.Email, jwt.TokenTypeMFAPending, 5*time.Minute)
	sudoToken, _ := jwtMgr.Issue(normalUser.ID, "user", normalUser.Email, jwt.TokenTypeSudo, 5*time.Minute)

	callAPI := func(method, path string, body any, authToken, extraHeaderKey, extraHeaderVal string) (int, string) {
		var reqBody []byte
		if body != nil {
			reqBody, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, path, bytes.NewBuffer(reqBody))
		req.RequestURI = path
		req.Header.Set("Content-Type", "application/json")
		if authToken != "" {
			req.Header.Set("Authorization", "Bearer "+authToken)
		}
		if extraHeaderKey != "" {
			req.Header.Set(extraHeaderKey, extraHeaderVal)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	assertNot404 := func(name, method, path string, code int, body string) {
		if code == http.StatusNotFound && (strings.Contains(body, "404 page not found") || strings.TrimSpace(body) == "404 page not found") {
			t.Fatalf("[%s] %s %s returned Gin 404 (endpoint not mounted!)", name, method, path)
		}
	}

	// =========================================================================
	// GROUP A: Operational & Probes (4 Endpoints)
	// =========================================================================
	t.Run("A. Operational Endpoints", func(t *testing.T) {
		// 1. GET /healthz
		code, resp := callAPI(http.MethodGet, "/healthz", nil, "", "", "")
		assertNot404("1. healthz", http.MethodGet, "/healthz", code, resp)
		if code != http.StatusOK {
			t.Errorf("/healthz want 200, got %d", code)
		}

		// 2. GET /readyz
		code, resp = callAPI(http.MethodGet, "/readyz", nil, "", "", "")
		assertNot404("2. readyz", http.MethodGet, "/readyz", code, resp)
		if code != http.StatusOK {
			t.Errorf("/readyz want 200, got %d", code)
		}

		// 3. GET /metrics
		code, resp = callAPI(http.MethodGet, "/metrics", nil, "", "", "")
		assertNot404("3. metrics", http.MethodGet, "/metrics", code, resp)
		if code != http.StatusOK {
			t.Errorf("/metrics want 200, got %d", code)
		}

		// 4. GET /swagger/*any
		code, resp = callAPI(http.MethodGet, "/swagger/index.html", nil, "", "", "")
		assertNot404("4. swagger", http.MethodGet, "/swagger/index.html", code, resp)
	})

	// =========================================================================
	// GROUP B: Public Core Auth & Credential Lifecycle (8 Endpoints)
	// =========================================================================
	t.Run("B. Public Core Auth Endpoints", func(t *testing.T) {
		// 5. POST /api/v1/auth/register
		code, resp := callAPI(http.MethodPost, "/api/v1/auth/register", map[string]any{
			"username": "newuser49", "email": "newuser49@enterprise.com", "password": rawPassword, "fullName": "New User",
		}, "", "", "")
		assertNot404("5. register", http.MethodPost, "/api/v1/auth/register", code, resp)
		if code != http.StatusCreated {
			t.Errorf("register want 201, got %d: %s", code, resp)
		}

		// 6. POST /api/v1/auth/login
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/login", map[string]any{
			"email": "newuser49@enterprise.com", "password": rawPassword,
		}, "", "", "")
		assertNot404("6. login", http.MethodPost, "/api/v1/auth/login", code, resp)
		if code != http.StatusOK {
			t.Fatalf("login want 200, got %d: %s", code, resp)
		}

		var loginData struct {
			Data struct {
				RefreshToken string `json:"refreshToken"`
			} `json:"data"`
		}
		_ = json.Unmarshal([]byte(resp), &loginData)
		rt := loginData.Data.RefreshToken

		// 7. POST /api/v1/auth/refresh-token
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/refresh-token", map[string]any{"refreshToken": rt}, "", "", "")
		assertNot404("7. refresh-token", http.MethodPost, "/api/v1/auth/refresh-token", code, resp)
		if code != http.StatusOK {
			t.Errorf("refresh-token want 200, got %d: %s", code, resp)
		}

		// 8. POST /api/v1/auth/forgot-password
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/forgot-password", map[string]any{"email": "newuser49@enterprise.com"}, "", "", "")
		assertNot404("8. forgot-password", http.MethodPost, "/api/v1/auth/forgot-password", code, resp)
		if code != http.StatusOK {
			t.Errorf("forgot-password want 200, got %d: %s", code, resp)
		}

		// 9. POST /api/v1/auth/reset-password
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/reset-password", map[string]any{"token": "invalid-token", "newPassword": rawPassword}, "", "", "")
		assertNot404("9. reset-password", http.MethodPost, "/api/v1/auth/reset-password", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("reset-password with invalid token want 401, got %d", code)
		}

		// 10. POST /api/v1/auth/verify-email
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/verify-email", map[string]any{"token": "invalid-token"}, "", "", "")
		assertNot404("10. verify-email", http.MethodPost, "/api/v1/auth/verify-email", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("verify-email with invalid token want 401, got %d", code)
		}

		// 11. POST /api/v1/auth/resend-verification
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/resend-verification", map[string]any{"email": "newuser49@enterprise.com"}, "", "", "")
		assertNot404("11. resend-verification", http.MethodPost, "/api/v1/auth/resend-verification", code, resp)
		if code != http.StatusOK {
			t.Errorf("resend-verification want 200, got %d: %s", code, resp)
		}

		// 12. POST /api/v1/auth/change-email/confirm
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/change-email/confirm", map[string]any{"token": "invalid-token"}, "", "", "")
		assertNot404("12. change-email/confirm", http.MethodPost, "/api/v1/auth/change-email/confirm", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("change-email/confirm with invalid token want 401, got %d", code)
		}
	})

	// =========================================================================
	// GROUP C: OAuth 2.0 / OpenID Connect (2 Endpoints)
	// =========================================================================
	t.Run("C. OAuth Endpoints", func(t *testing.T) {
		// 13. GET /api/v1/auth/google/login
		code, resp := callAPI(http.MethodGet, "/api/v1/auth/google/login", nil, "", "", "")
		assertNot404("13. google/login", http.MethodGet, "/api/v1/auth/google/login", code, resp)
		if code != http.StatusOK && code != http.StatusFound && code != http.StatusTemporaryRedirect {
			t.Errorf("google/login want 200, 302 or 307, got %d", code)
		}

		// 14. GET /api/v1/auth/google/callback
		code, resp = callAPI(http.MethodGet, "/api/v1/auth/google/callback?code=mock-code&state=test-state-123", nil, "", "Cookie", "finnapigo_oauth_state=test-state-123")
		assertNot404("14. google/callback", http.MethodGet, "/api/v1/auth/google/callback", code, resp)
		if code != http.StatusOK {
			t.Errorf("google/callback want 200, got %d: %s", code, resp)
		}
	})

	// =========================================================================
	// GROUP D: Authenticated User Profile & Identity (10 Endpoints)
	// =========================================================================
	t.Run("D. Authenticated Profile Endpoints", func(t *testing.T) {
		tok := freshUserToken()

		// 15. POST /api/v1/auth/logout (Auth gate)
		code, resp := callAPI(http.MethodPost, "/api/v1/auth/logout", nil, "", "", "")
		assertNot404("15. logout unauth", http.MethodPost, "/api/v1/auth/logout", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("logout unauth want 401, got %d", code)
		}
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/logout", map[string]any{"refreshToken": "dummy"}, tok, "", "")
		assertNot404("15. logout auth", http.MethodPost, "/api/v1/auth/logout", code, resp)
		if code != http.StatusOK {
			t.Errorf("logout auth want 200, got %d: %s", code, resp)
		}

		// 16. POST /api/v1/auth/logout-all
		tok = freshUserToken()
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/logout-all", nil, tok, "", "")
		assertNot404("16. logout-all", http.MethodPost, "/api/v1/auth/logout-all", code, resp)
		if code != http.StatusOK {
			t.Errorf("logout-all want 200, got %d: %s", code, resp)
		}

		// 17. POST /api/v1/auth/change-password
		tok = freshUserToken()
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/change-password", map[string]any{"oldPassword": "wrong", "newPassword": rawPassword}, tok, "", "")
		assertNot404("17. change-password", http.MethodPost, "/api/v1/auth/change-password", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("change-password with wrong old password want 401, got %d", code)
		}

		// 18. POST /api/v1/auth/set-password (User already has password -> 409 Conflict)
		tok = freshUserToken()
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/set-password", map[string]any{"password": rawPassword}, tok, "", "")
		assertNot404("18. set-password", http.MethodPost, "/api/v1/auth/set-password", code, resp)
		if code != http.StatusConflict {
			t.Errorf("set-password for existing password account want 409, got %d", code)
		}

		// 19. GET /api/v1/auth/me
		tok = freshUserToken()
		code, resp = callAPI(http.MethodGet, "/api/v1/auth/me", nil, tok, "", "")
		assertNot404("19. me", http.MethodGet, "/api/v1/auth/me", code, resp)
		if code != http.StatusOK {
			t.Errorf("me want 200, got %d", code)
		}

		// 20. DELETE /api/v1/auth/me (Account erasure wrong pwd -> 401)
		tok = freshUserToken()
		code, resp = callAPI(http.MethodDelete, "/api/v1/auth/me", map[string]any{"password": "wrong"}, tok, "", "")
		assertNot404("20. delete me", http.MethodDelete, "/api/v1/auth/me", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("delete me wrong pwd want 401, got %d", code)
		}

		// 21. GET /api/v1/auth/me/audit-log
		tok = freshUserToken()
		code, resp = callAPI(http.MethodGet, "/api/v1/auth/me/audit-log", nil, tok, "", "")
		assertNot404("21. me/audit-log", http.MethodGet, "/api/v1/auth/me/audit-log", code, resp)
		if code != http.StatusOK {
			t.Errorf("me/audit-log want 200, got %d", code)
		}

		// 22. POST /api/v1/auth/change-email/request
		tok = freshUserToken()
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/change-email/request", map[string]any{"newEmail": "new_email@enterprise.com", "password": rawPassword}, tok, "", "")
		assertNot404("22. change-email/request", http.MethodPost, "/api/v1/auth/change-email/request", code, resp)
		if code != http.StatusOK {
			t.Errorf("change-email/request want 200, got %d: %s", code, resp)
		}

		// 23. POST /api/v1/auth/deactivate (wrong pwd -> 401)
		tok = freshUserToken()
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/deactivate", map[string]any{"password": "wrong"}, tok, "", "")
		assertNot404("23. deactivate", http.MethodPost, "/api/v1/auth/deactivate", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("deactivate wrong pwd want 401, got %d", code)
		}

		// 24. DELETE /api/v1/auth/oauth/:provider
		tok = freshUserToken()
		code, resp = callAPI(http.MethodDelete, "/api/v1/auth/oauth/google", nil, tok, "", "")
		assertNot404("24. oauth unlink", http.MethodDelete, "/api/v1/auth/oauth/google", code, resp)
		if code != http.StatusOK {
			t.Errorf("oauth unlink want 200, got %d: %s", code, resp)
		}
	})

	// =========================================================================
	// GROUP E: Session Management (2 Endpoints)
	// =========================================================================
	t.Run("E. Session Management Endpoints", func(t *testing.T) {
		tok := freshUserToken()

		// 25. GET /api/v1/auth/sessions
		code, resp := callAPI(http.MethodGet, "/api/v1/auth/sessions", nil, tok, "", "")
		assertNot404("25. sessions list", http.MethodGet, "/api/v1/auth/sessions", code, resp)
		if code != http.StatusOK {
			t.Errorf("sessions list want 200, got %d: %s", code, resp)
		}

		// 26. DELETE /api/v1/auth/sessions/:id
		code, resp = callAPI(http.MethodDelete, "/api/v1/auth/sessions/sess-user-secondary", nil, tok, "", "")
		assertNot404("26. sessions revoke", http.MethodDelete, "/api/v1/auth/sessions/sess-user-secondary", code, resp)
		if code != http.StatusOK {
			t.Errorf("sessions revoke want 200, got %d: %s", code, resp)
		}
	})

	// =========================================================================
	// GROUP F: Trusted Devices (2 Endpoints)
	// =========================================================================
	t.Run("F. Trusted Devices Endpoints", func(t *testing.T) {
		tok := freshUserToken()

		// 27. GET /api/v1/auth/trusted-devices
		code, resp := callAPI(http.MethodGet, "/api/v1/auth/trusted-devices", nil, tok, "", "")
		assertNot404("27. trusted-devices list", http.MethodGet, "/api/v1/auth/trusted-devices", code, resp)
		if code != http.StatusOK {
			t.Errorf("trusted-devices list want 200, got %d: %s", code, resp)
		}

		// 28. DELETE /api/v1/auth/trusted-devices/:id
		code, resp = callAPI(http.MethodDelete, "/api/v1/auth/trusted-devices/1", nil, tok, "", "")
		assertNot404("28. trusted-devices revoke", http.MethodDelete, "/api/v1/auth/trusted-devices/1", code, resp)
		if code != http.StatusOK {
			t.Errorf("trusted-devices revoke want 200, got %d: %s", code, resp)
		}
	})

	// =========================================================================
	// GROUP G: MFA Pending Gate (1 Endpoint)
	// =========================================================================
	t.Run("G. MFA Pending Gate Endpoint", func(t *testing.T) {
		tok := freshUserToken()

		// 29. POST /api/v1/auth/mfa/login-verify
		// Rejected if calling with regular access token (security isolation)
		code, resp := callAPI(http.MethodPost, "/api/v1/auth/mfa/login-verify", map[string]any{"code": "123456"}, tok, "", "")
		assertNot404("29. login-verify with access token", http.MethodPost, "/api/v1/auth/mfa/login-verify", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("login-verify with access token want 401, got %d", code)
		}

		// Calling with mfa_pending token
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/login-verify", map[string]any{"code": "123456"}, mfaPendingToken, "", "")
		assertNot404("29. login-verify with mfa_pending token", http.MethodPost, "/api/v1/auth/mfa/login-verify", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("login-verify with mfa_pending token and unconfigured user want 401, got %d", code)
		}
	})

	// =========================================================================
	// GROUP H: TOTP MFA Ceremonies (7 Endpoints)
	// =========================================================================
	t.Run("H. TOTP MFA Endpoints", func(t *testing.T) {
		tok := freshUserToken()

		// 30. POST /api/v1/auth/mfa/totp/enable
		code, resp := callAPI(http.MethodPost, "/api/v1/auth/mfa/totp/enable", nil, tok, "", "")
		assertNot404("30. totp/enable", http.MethodPost, "/api/v1/auth/mfa/totp/enable", code, resp)
		if code != http.StatusOK {
			t.Errorf("totp/enable want 200, got %d: %s", code, resp)
		}

		// 31. POST /api/v1/auth/mfa/totp/verify
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/totp/verify", map[string]any{"code": "000000"}, tok, "", "")
		assertNot404("31. totp/verify", http.MethodPost, "/api/v1/auth/mfa/totp/verify", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("totp/verify invalid code want 401, got %d", code)
		}

		// 32. POST /api/v1/auth/mfa/totp/validate
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/totp/validate", map[string]any{"code": "000000"}, tok, "", "")
		assertNot404("32. totp/validate", http.MethodPost, "/api/v1/auth/mfa/totp/validate", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("totp/validate invalid code want 401, got %d", code)
		}

		// 33. POST /api/v1/auth/mfa/totp/recovery-codes
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/totp/recovery-codes", map[string]any{"code": "000000"}, tok, "", "")
		assertNot404("33. totp/recovery-codes", http.MethodPost, "/api/v1/auth/mfa/totp/recovery-codes", code, resp)
		if code != http.StatusUnauthorized {
			t.Errorf("totp/recovery-codes invalid code want 401, got %d", code)
		}

		// 34. POST /api/v1/auth/mfa/totp/disable
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/totp/disable", map[string]any{"code": "000000"}, tok, "", "")
		assertNot404("34. totp/disable", http.MethodPost, "/api/v1/auth/mfa/totp/disable", code, resp)
		if code != http.StatusOK {
			t.Errorf("totp/disable idempotent want 200, got %d", code)
		}

		// 35. GET /api/v1/auth/mfa/methods
		code, resp = callAPI(http.MethodGet, "/api/v1/auth/mfa/methods", nil, tok, "", "")
		assertNot404("35. mfa/methods", http.MethodGet, "/api/v1/auth/mfa/methods", code, resp)
		if code != http.StatusOK {
			t.Errorf("mfa/methods want 200, got %d: %s", code, resp)
		}

		// 36. POST /api/v1/auth/mfa/totp/recovery-codes/regenerate (Sudo mode required)
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/totp/recovery-codes/regenerate", nil, tok, "", "")
		assertNot404("36. regenerate recovery codes (without sudo)", http.MethodPost, "/api/v1/auth/mfa/totp/recovery-codes/regenerate", code, resp)
		if code != http.StatusForbidden {
			t.Errorf("regenerate recovery codes without sudo want 403, got %d", code)
		}
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/totp/recovery-codes/regenerate", nil, tok, "X-Sudo-Token", sudoToken)
		assertNot404("36. regenerate recovery codes (with sudo)", http.MethodPost, "/api/v1/auth/mfa/totp/recovery-codes/regenerate", code, resp)
		// With valid sudoToken, handler is reached (returns 401 because TOTP device not confirmed yet, proving sudo gate passed)
		if code != http.StatusUnauthorized {
			t.Errorf("regenerate recovery codes with sudo for unconfirmed device want 401, got %d", code)
		}
	})

	// =========================================================================
	// GROUP I: Passkey / WebAuthn Ceremonies (6 Endpoints)
	// =========================================================================
	t.Run("I. Passkey WebAuthn Endpoints", func(t *testing.T) {
		tok := freshUserToken()

		// 37. POST /api/v1/auth/mfa/passkey/register/challenge
		code, resp := callAPI(http.MethodPost, "/api/v1/auth/mfa/passkey/register/challenge", map[string]any{"displayName": "MacBook Key"}, tok, "", "")
		assertNot404("37. passkey register challenge", http.MethodPost, "/api/v1/auth/mfa/passkey/register/challenge", code, resp)
		if code != http.StatusOK {
			t.Errorf("passkey register challenge want 200, got %d: %s", code, resp)
		}

		// 38. POST /api/v1/auth/mfa/passkey/register/verify
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/passkey/register/verify", map[string]any{"invalid": "data"}, tok, "", "")
		assertNot404("38. passkey register verify", http.MethodPost, "/api/v1/auth/mfa/passkey/register/verify", code, resp)
		if code != http.StatusBadRequest && code != http.StatusInternalServerError {
			t.Errorf("passkey register verify invalid data want 400 or 500, got %d", code)
		}

		// 39. POST /api/v1/auth/mfa/passkey/authenticate/challenge
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/passkey/authenticate/challenge", nil, tok, "", "")
		assertNot404("39. passkey auth challenge", http.MethodPost, "/api/v1/auth/mfa/passkey/authenticate/challenge", code, resp)
		if code != http.StatusOK {
			t.Errorf("passkey auth challenge want 200, got %d: %s", code, resp)
		}

		// 40. POST /api/v1/auth/mfa/passkey/authenticate/verify
		code, resp = callAPI(http.MethodPost, "/api/v1/auth/mfa/passkey/authenticate/verify", map[string]any{"invalid": "assertion"}, tok, "", "")
		assertNot404("40. passkey auth verify", http.MethodPost, "/api/v1/auth/mfa/passkey/authenticate/verify", code, resp)
		if code != http.StatusBadRequest && code != http.StatusInternalServerError {
			t.Errorf("passkey auth verify invalid assertion want 400 or 500, got %d", code)
		}

		// 41. GET /api/v1/auth/mfa/passkeys
		code, resp = callAPI(http.MethodGet, "/api/v1/auth/mfa/passkeys", nil, tok, "", "")
		assertNot404("41. passkeys list", http.MethodGet, "/api/v1/auth/mfa/passkeys", code, resp)
		if code != http.StatusOK {
			t.Errorf("passkeys list want 200, got %d: %s", code, resp)
		}

		// 42. DELETE /api/v1/auth/mfa/passkeys/:id (Sudo gated)
		code, resp = callAPI(http.MethodDelete, "/api/v1/auth/mfa/passkeys/1", nil, tok, "", "")
		assertNot404("42. passkey revoke (without sudo)", http.MethodDelete, "/api/v1/auth/mfa/passkeys/1", code, resp)
		if code != http.StatusForbidden {
			t.Errorf("passkey revoke without sudo want 403, got %d", code)
		}
		code, resp = callAPI(http.MethodDelete, "/api/v1/auth/mfa/passkeys/1", nil, tok, "X-Sudo-Token", sudoToken)
		assertNot404("42. passkey revoke (with sudo)", http.MethodDelete, "/api/v1/auth/mfa/passkeys/1", code, resp)
		if code != http.StatusOK {
			t.Errorf("passkey revoke with sudo want 200, got %d: %s", code, resp)
		}
	})

	// =========================================================================
	// GROUP J: Enterprise Admin & Webhook Governance (7 Endpoints)
	// =========================================================================
	t.Run("J. Enterprise Admin Endpoints", func(t *testing.T) {
		tok := freshUserToken()
		admTok := freshAdminToken()

		// 43. GET /api/v1/admin/users
		// User token lacking users:read -> 403 Forbidden
		code, resp := callAPI(http.MethodGet, "/api/v1/admin/users", nil, tok, "", "")
		assertNot404("43. admin users (user token)", http.MethodGet, "/api/v1/admin/users", code, resp)
		if code != http.StatusForbidden {
			t.Errorf("admin users without permission want 403, got %d", code)
		}
		// Admin token -> 200 OK
		code, resp = callAPI(http.MethodGet, "/api/v1/admin/users", nil, admTok, "", "")
		if code != http.StatusOK {
			t.Errorf("admin users with admin token want 200, got %d: %s", code, resp)
		}

		// 44. POST /api/v1/admin/users/:id/lock
		// Self-lockout prevention check
		code, resp = callAPI(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/lock", adminUser.ID), map[string]any{"durationSeconds": 3600}, admTok, "", "")
		assertNot404("44. admin lock self", http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/lock", adminUser.ID), code, resp)
		if code != http.StatusBadRequest {
			t.Errorf("admin locking self want 400, got %d", code)
		}
		// Lock normal user
		code, resp = callAPI(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/lock", normalUser.ID), map[string]any{"durationSeconds": 3600}, admTok, "", "")
		if code != http.StatusOK {
			t.Errorf("admin locking normal user want 200, got %d: %s", code, resp)
		}

		// 45. POST /api/v1/admin/users/:id/unlock
		code, resp = callAPI(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/unlock", normalUser.ID), nil, admTok, "", "")
		assertNot404("45. admin unlock", http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/unlock", normalUser.ID), code, resp)
		if code != http.StatusOK {
			t.Errorf("admin unlocking user want 200, got %d: %s", code, resp)
		}

		// 46. POST /api/v1/admin/users/:id/force-logout
		code, resp = callAPI(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/force-logout", normalUser.ID), nil, admTok, "", "")
		assertNot404("46. admin force-logout", http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/force-logout", normalUser.ID), code, resp)
		if code != http.StatusOK {
			t.Errorf("admin force-logout want 200, got %d: %s", code, resp)
		}

		// 47. GET /api/v1/admin/sessions
		code, resp = callAPI(http.MethodGet, "/api/v1/admin/sessions", nil, tok, "", "")
		assertNot404("47. admin sessions (user token)", http.MethodGet, "/api/v1/admin/sessions", code, resp)
		if code != http.StatusForbidden {
			t.Errorf("admin sessions without permission want 403, got %d", code)
		}
		code, resp = callAPI(http.MethodGet, "/api/v1/admin/sessions", nil, admTok, "", "")
		if code != http.StatusOK {
			t.Errorf("admin sessions with admin token want 200, got %d: %s", code, resp)
		}

		// 48. GET /api/v1/admin/audit-log/export
		code, resp = callAPI(http.MethodGet, "/api/v1/admin/audit-log/export", nil, tok, "", "")
		assertNot404("48. admin export (user token)", http.MethodGet, "/api/v1/admin/audit-log/export", code, resp)
		if code != http.StatusForbidden {
			t.Errorf("admin export without permission want 403, got %d", code)
		}
		code, resp = callAPI(http.MethodGet, "/api/v1/admin/audit-log/export", nil, admTok, "", "")
		if code != http.StatusOK {
			t.Errorf("admin export with admin token want 200, got %d: %s", code, resp)
		}

		// 49. POST /api/v1/admin/webhooks
		// SSRF protection: loopback and private IPs are blocked
		code, resp = callAPI(http.MethodPost, "/api/v1/admin/webhooks", map[string]any{"url": "http://127.0.0.1:8080/internal", "events": "user.created"}, admTok, "", "")
		assertNot404("49. admin webhooks (ssrf attempt)", http.MethodPost, "/api/v1/admin/webhooks", code, resp)
		if code != http.StatusBadRequest {
			t.Errorf("admin webhook ssrf target want 400, got %d", code)
		}
		// Valid registration using test fixture allowLocalhost
		webhookSvc.SetAllowLocalhost(true)
		code, resp = callAPI(http.MethodPost, "/api/v1/admin/webhooks", map[string]any{"url": "http://localhost:8080/webhook", "events": "user.created"}, admTok, "", "")
		webhookSvc.SetAllowLocalhost(false)
		assertNot404("49. admin webhooks (valid registration)", http.MethodPost, "/api/v1/admin/webhooks", code, resp)
		if code != http.StatusCreated {
			t.Errorf("admin webhook valid url want 201, got %d: %s", code, resp)
		}
	})
}
