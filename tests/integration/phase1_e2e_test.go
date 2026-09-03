package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestE2E_Phase1_UserLifecycle verifies the complete Phase 1 lifecycle on an in-memory SQLite DB.
func TestE2E_Phase1_UserLifecycle(t *testing.T) {
	ctx := context.Background()

	// 1. Setup in-memory SQLite DB
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	// Auto-migrate tables
	err = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.Session{},
		&models.AuditLog{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
		&models.PasskeyCredential{},
		&models.OAuthIdentity{},
	)
	if err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	// 2. Setup Repositories
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)

	kvStore := store.NewInMemoryStore(time.Minute)
	jwtMgr := jwt.NewJWTManager("test-jwt-secret-key-32-chars-long!!", "test-issuer")

	enc, _ := crypto.NewEncryptor([]byte("01234567890123456789012345678901"))

	authCfg := config.AuthConfig{
		TOTPMaxAttempts:   5,
		TOTPAttemptWindow: 5 * time.Minute,
		RecoveryCodeCount: 5,
		RecoveryCodeBytes: 16,
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
	)

	oauthSvc := services.NewOAuthService(
		userRepo, oauthRepo, kvStore, authSvc, nil, nil,
		services.WithOAuthAudits(auditRepo),
		services.WithOAuthPasskeys(passkeyRepo),
	)

	// 3. Register user
	pwdHash, _ := hash.HashPassword("StrongP@ssw0rd!2026")
	user := &models.User{
		Email:           "enterprise@example.com",
		Username:        "enterprise_user",
		Password:        pwdHash,
		FullName:        "Enterprise User",
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	// 4. Link OAuth Identity
	err = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-sub-enterprise",
	})
	if err != nil {
		t.Fatalf("Create oauth link failed: %v", err)
	}

	// 5. Create Passkey
	err = passkeyRepo.Create(ctx, &models.PasskeyCredential{
		UserID:       user.ID,
		CredentialID: []byte("cred-enterprise-1"),
		PublicKey:    []byte("enterprise-public-key"),
		Revoked:      false,
	})
	if err != nil {
		t.Fatalf("Create passkey failed: %v", err)
	}

	// 6. Record Audit Log
	auditRepo.Record(ctx, &models.AuditLog{
		UserID:    &user.ID,
		Email:     user.Email,
		Event:     models.AuditEventLogin,
		IPAddress: "192.168.1.1",
		Success:   true,
	})

	// 7. Verify MFA methods aggregation across components
	methods, err := totpSvc.GetMFAMethods(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetMFAMethods failed: %v", err)
	}
	if methods.PasskeysCount != 1 || methods.DefaultMethod != "passkey" {
		t.Fatalf("unexpected MFA methods: %+v", methods)
	}

	// 8. Verify OAuth Unlink with password
	err = oauthSvc.Unlink(ctx, user.ID, "google", "192.168.1.1")
	if err != nil {
		t.Fatalf("Unlink google failed: %v", err)
	}
	link, _ := oauthRepo.FindByUserIDAndProvider(ctx, user.ID, "google")
	if link != nil {
		t.Fatal("expected google identity unlinked")
	}

	// Re-link google
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-sub-enterprise",
	})

	// 9. Execute GDPR Right to Erasure
	err = authSvc.EraseAccount(ctx, user.ID, "", "StrongP@ssw0rd!2026", "dummy-access-jti", "192.168.1.1")
	if err != nil {
		t.Fatalf("EraseAccount failed: %v", err)
	}

	// 10. Verify Data Scrubbing
	erased, err := userRepo.FindByID(ctx, user.ID)
	if err != nil || erased == nil {
		t.Fatalf("FindByID failed: %v", err)
	}
	if !strings.HasPrefix(erased.Email, "deleted_") || erased.Password != "" || erased.FullName != "" || erased.IsActive {
		t.Fatalf("user was not scrubbed: %+v", erased)
	}

	// Passkeys revoked
	activePasskeys, _ := passkeyRepo.ListByUser(ctx, user.ID, false)
	if len(activePasskeys) != 0 {
		t.Fatalf("passkeys were not revoked: %d active remain", len(activePasskeys))
	}

	// OAuth identities deleted
	ident, _ := oauthRepo.FindByUserIDAndProvider(ctx, user.ID, "google")
	if ident != nil {
		t.Fatal("oauth identities were not deleted")
	}

	// Audit logs anonymized
	logs, _, _ := auditRepo.FindByUserIDPaginated(ctx, user.ID, 1, 10)
	for _, l := range logs {
		if l.Event == models.AuditEventLogin && l.Email != "anonymized@gdpr.local" {
			t.Fatalf("audit email not anonymized: got %s, want anonymized@gdpr.local", l.Email)
		}
	}
}
