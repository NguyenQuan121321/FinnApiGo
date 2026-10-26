package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/identity"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

func TestSharedIssuanceV1AndDurableLogout(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "default")
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	defer func() { _ = conn.Close() }()
	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.Session{}, &models.AccessRevocation{}, &models.Tenant{}, &models.AuditLog{}, &models.AuditHead{}, &models.AuditOutbox{}, &models.AuditBoundary{}, &models.UsedToken{}, &models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.Tenant{ID: "default", Slug: "default", Name: "Default", IsActive: true}).Error; err != nil {
		t.Fatal(err)
	}
	users := repositories.NewUserRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)
	sessions := repositories.NewSessionRepository(db)
	rbac := repositories.NewRBACRepository(db)
	s := store.NewInMemoryStore(0)
	defer s.Close()
	key := sha256.Sum256([]byte("F02 public synthetic shared issuance key"))
	m, err := jwt.NewConfiguredJWTManager(jwt.KeyConfig{Algorithm: "HS256", CurrentID: "fixture", CurrentSecret: base64.StdEncoding.EncodeToString(key[:])})
	if err != nil {
		t.Fatal(err)
	}
	a := &identity.Authority{DB: db, Store: s}
	svc := NewAuthService(users, tokens, repositories.NewUsedTokenRepository(db), repositories.NewAuditRepository(db), s, m, config.AuthConfig{BcryptCost: hash.MinCost}, config.RateLimitConfig{}, config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour}, &mockNotifier{}, nil, nil, nil, nil, WithSessionRepo(sessions), WithAuthPermissions(rbac), WithAccessRevoker(a), WithAccessState(a.Check))
	u := &models.User{Username: "synthetic", Email: "synthetic@example.invalid", Password: "hash", IsActive: true, IsEmailVerified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	pair, _, err := svc.IssuePasskeyTokenPair(ctx, u, "127.0.0.1", "synthetic browser")
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.VerifyAccessV1(pair.AccessToken, jwt.FinnAudience)
	if err != nil {
		t.Fatal(err)
	}
	if c.SID == "" || c.Permissions == nil || c.ContractVersion != 1 {
		t.Fatal("shared path omitted v1 claims")
	}
	if _, err := m.VerifyAccessV1(pair.AccessToken, jwt.JakeAudience); err == nil {
		t.Fatal("empty permissions granted Jake audience")
	}
	rotated, err := svc.Refresh(ctx, pair.RefreshToken, "127.0.0.1", "synthetic browser")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := m.VerifyAccessV1(rotated.AccessToken, jwt.FinnAudience)
	if err != nil {
		t.Fatal(err)
	}
	if rc.SID != c.SID {
		t.Fatal("refresh changed session")
	}
	if err := svc.Logout(ctx, rotated.RefreshToken, rc.ID, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := a.Check(ctx, rc); !errors.Is(err, identity.ErrInactive) {
		t.Fatal("logout did not revoke")
	}
	var count int64
	if err := db.Model(&models.AccessRevocation{}).Where("tenant_id = ? AND jti = ?", "default", rc.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatal("logout missing durable JTI")
	}
	u.AdminSuspended = true
	if _, _, _, err := svc.CheckMFAOrIssueTokens(ctx, u, "127.0.0.1", "synthetic", ""); !errors.Is(err, ErrAccountDisabled) {
		t.Fatal("suspended pre-MFA issuance accepted")
	}
	u.AdminSuspended = false
	svc.accessState = func(context.Context, *jwt.Claims) error { return errors.New("dependency down") }
	if _, _, err := svc.IssuePasskeyTokenPair(ctx, u, "127.0.0.1", "synthetic"); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatal("state failure issued credentials")
	}
	svc.permissions = nil
	if _, _, err := svc.IssuePasskeyTokenPair(ctx, u, "127.0.0.1", "synthetic"); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatal("missing authority issued credentials")
	}
}
