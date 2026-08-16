package repositories

// These repository tests use a private in-memory SQLite database for fast,
// isolated CRUD coverage. MySQL-specific duplicate error 1062 mapping is
// deliberately covered with fakes in services tests, not forced through SQLite.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.AuditLog{}, &models.UsedToken{}, &models.OAuthIdentity{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func testUser(t *testing.T, db *gorm.DB) *models.User {
	t.Helper()
	u := &models.User{Username: "alice", Email: "alice@example.com", Password: "hash", Role: models.RoleUser, IsActive: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func TestOAuthIdentityRepository(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	repo := NewOAuthIdentityRepository(db)

	ident := &models.OAuthIdentity{UserID: u.ID, Provider: "google", ProviderUserID: "sub-123"}
	if err := repo.Create(ctx, ident); err != nil {
		t.Fatal(err)
	}

	got, err := repo.FindByProviderAndProviderUserID(ctx, "google", "sub-123")
	if err != nil || got == nil || got.UserID != u.ID {
		t.Fatalf("FindByProviderAndProviderUserID=%+v err=%v", got, err)
	}
	if got, err := repo.FindByProviderAndProviderUserID(ctx, "google", "nope"); err != nil || got != nil {
		t.Fatalf("missing identity: got=%+v err=%v", got, err)
	}
	if got, err := repo.FindByUserIDAndProvider(ctx, u.ID, "google"); err != nil || got == nil || got.ProviderUserID != "sub-123" {
		t.Fatalf("FindByUserIDAndProvider=%+v err=%v", got, err)
	}

	// (provider, provider_user_id) uniqueness: linking the same Google account
	// to a second user must be rejected by the composite unique index.
	dup := &models.OAuthIdentity{UserID: u.ID + 1, Provider: "google", ProviderUserID: "sub-123"}
	if err := repo.Create(ctx, dup); err == nil {
		t.Fatal("expected duplicate (provider, provider_user_id) to be rejected")
	}
	// A second Google account for the same user is fine (multi-account edge).
	second := &models.OAuthIdentity{UserID: u.ID, Provider: "google", ProviderUserID: "sub-456"}
	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("second identity for same user: %v", err)
	}
}

func TestUserRepository(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository(testDB(t))
	u := &models.User{Username: "alice", Email: "alice@example.com", Password: "hash", Role: models.RoleUser, IsActive: true}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.FindByEmail(ctx, u.Email); err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("FindByEmail=%+v err=%v", got, err)
	}
	if got, err := repo.FindByUsername(ctx, u.Username); err != nil || got == nil {
		t.Fatalf("FindByUsername=%+v err=%v", got, err)
	}
	if got, err := repo.FindByID(ctx, 999); err != nil || got != nil {
		t.Fatalf("missing=%+v err=%v", got, err)
	}
	if err := repo.UpdatePassword(ctx, u, "next"); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	if err := repo.IncrementFailedAttempts(ctx, u, &until); err != nil {
		t.Fatal(err)
	}
	if err := repo.ResetFailedAttempts(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetEmailVerified(ctx, u, true); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.FindByID(ctx, u.ID)
	if got.Password != "next" || !got.IsEmailVerified || got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
		t.Fatalf("unexpected user state: %+v", got)
	}
}

func TestRefreshTokenRepository(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	repo := NewRefreshTokenRepository(db)
	active := &models.RefreshToken{UserID: u.ID, TokenHash: "active", ExpiresAt: time.Now().Add(time.Hour)}
	expired := &models.RefreshToken{UserID: u.ID, TokenHash: "expired", ExpiresAt: time.Now().Add(-time.Hour)}
	if err := repo.Create(ctx, active); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.FindByHash(ctx, "missing"); err != nil || got != nil {
		t.Fatalf("missing=%+v err=%v", got, err)
	}
	if err := repo.Revoke(ctx, active); err != nil || !active.Revoked {
		t.Fatalf("Revoke err=%v", err)
	}
	if err := repo.RevokeAllForUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.PurgeExpired(ctx, time.Now()); err != nil || n != 2 {
		t.Fatalf("PurgeExpired n=%d err=%v", n, err)
	}
}

func TestRefreshTokenRepository_FindActiveByUser(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	u2 := &models.User{Username: "bob", Email: "bob@example.com", Password: "h", Role: models.RoleUser, IsActive: true}
	if err := db.Create(u2).Error; err != nil {
		t.Fatal(err)
	}
	repo := NewRefreshTokenRepository(db)

	// user u: two active sessions + one revoked + one expired
	now := time.Now()
	sessA := &models.RefreshToken{UserID: u.ID, TokenHash: "a", ExpiresAt: now.Add(time.Hour), LastActiveAt: now, DeviceName: "Chrome on Windows"}
	sessB := &models.RefreshToken{UserID: u.ID, TokenHash: "b", ExpiresAt: now.Add(2 * time.Hour), LastActiveAt: now.Add(-time.Minute), DeviceName: "Safari on iPhone"}
	revoked := &models.RefreshToken{UserID: u.ID, TokenHash: "rev", ExpiresAt: now.Add(time.Hour), Revoked: true}
	expired := &models.RefreshToken{UserID: u.ID, TokenHash: "exp", ExpiresAt: now.Add(-time.Hour)}
	for _, rt := range []*models.RefreshToken{sessA, sessB, revoked, expired} {
		if err := repo.Create(ctx, rt); err != nil {
			t.Fatal(err)
		}
	}
	// user u2: one active (should NOT appear in u1's listing)
	other := &models.RefreshToken{UserID: u2.ID, TokenHash: "other", ExpiresAt: now.Add(time.Hour)}
	if err := repo.Create(ctx, other); err != nil {
		t.Fatal(err)
	}

	rows, err := repo.FindActiveByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindActiveByUser err=%v", err)
	}
	// Only sessA + sessB should appear (revoked + expired filtered, u2 excluded).
	if len(rows) != 2 {
		t.Fatalf("len(active) = %d, want 2", len(rows))
	}
	// sessA is newest activity (now > now-1min) → should be first.
	if rows[0].TokenHash != "a" {
		t.Errorf("first row hash = %q, want %q", rows[0].TokenHash, "a")
	}
	if rows[1].TokenHash != "b" {
		t.Errorf("second row hash = %q, want %q", rows[1].TokenHash, "b")
	}
}

// TestRefreshTokenRepository_RevokeCAS_C1 — C1 regression: Revoke must be a
// compare-and-set. Revoking an already-revoked row must report
// ErrTokenAlreadyRevoked instead of silently succeeding, so a concurrent
// double-refresh of one token can be detected as reuse.
func TestRefreshTokenRepository_RevokeCAS_C1(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	repo := NewRefreshTokenRepository(db)
	rt := &models.RefreshToken{UserID: u.ID, TokenHash: "cas", ExpiresAt: time.Now().Add(time.Hour)}
	if err := repo.Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, rt); err != nil {
		t.Fatalf("first Revoke err=%v", err)
	}
	if err := repo.Revoke(ctx, rt); !errors.Is(err, ErrTokenAlreadyRevoked) {
		t.Fatalf("second Revoke must return ErrTokenAlreadyRevoked, got %v", err)
	}
	got, err := repo.FindByHash(ctx, "cas")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Error("row must remain revoked after rejected second Revoke")
	}
}

func TestRefreshTokenRepository_RevokeByID(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	repo := NewRefreshTokenRepository(db)
	rt := &models.RefreshToken{UserID: u.ID, TokenHash: "target", ExpiresAt: time.Now().Add(time.Hour)}
	if err := repo.Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	// RevokeByID scoped to correct user must succeed.
	if err := repo.RevokeByID(ctx, rt.ID, u.ID); err != nil {
		t.Fatalf("RevokeByID err=%v", err)
	}
	// Verify it is actually revoked.
	got, err := repo.FindByHash(ctx, "target")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Error("expected Revoked=true after RevokeByID")
	}
	// RevokeByID scoped to WRONG user → not found.
	err = repo.RevokeByID(ctx, rt.ID, u.ID+1)
	if err == nil {
		t.Fatal("expected error when revoking other user's session")
	}
}

func TestRefreshTokenRepository_TouchLastActive(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	repo := NewRefreshTokenRepository(db)
	rt := &models.RefreshToken{UserID: u.ID, TokenHash: "touch", ExpiresAt: time.Now().Add(time.Hour), LastActiveAt: time.Now().Add(-time.Hour)}
	if err := repo.Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	original := rt.LastActiveAt
	if err := repo.TouchLastActive(ctx, rt.ID); err != nil {
		t.Fatalf("TouchLastActive err=%v", err)
	}
	got, err := repo.FindByHash(ctx, "touch")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastActiveAt.After(original) {
		t.Error("expected LastActiveAt to be bumped")
	}
}

func TestUsedTokenRepository(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	usedRepo := NewUsedTokenRepository(db)
	if marked, err := usedRepo.MarkUsed(ctx, "jti", "verify", u.ID, time.Now().Add(time.Hour)); err != nil || !marked {
		t.Fatalf("marked=%t err=%v", marked, err)
	}
	if used, err := usedRepo.IsUsed(ctx, "jti"); err != nil || !used {
		t.Fatalf("used=%t err=%v", used, err)
	}
	if n, err := usedRepo.PurgeExpired(ctx, time.Now().Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("purge=%d err=%v", n, err)
	}
}

func TestAuditRepository(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	repo := NewAuditRepository(db)
	repo.Record(ctx, &models.AuditLog{Event: models.AuditEventLogin, Success: true})
	if n := repo.BatchInsert(ctx, []*models.AuditLog{{Event: models.AuditEventLogout}, {Event: models.AuditEventTOTPEnabled}}); n != 2 {
		t.Fatalf("BatchInsert=%d", n)
	}
	var count int64
	if err := db.Model(&models.AuditLog{}).Count(&count).Error; err != nil || count != 3 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

// TestTOTPRepository_MarkRecoveryCodeUsedCAS_C2 — C2 regression: marking a
// recovery code used must be a compare-and-set on used_at IS NULL so the
// second of two concurrent submissions is rejected instead of silently
// succeeding twice.
func TestTOTPRepository_MarkRecoveryCodeUsedCAS_C2(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	if err := db.AutoMigrate(&models.TOTPDevice{}, &models.RecoveryCode{}); err != nil {
		t.Fatal(err)
	}
	repo := NewTOTPRepository(db)
	if err := repo.Upsert(ctx, &models.TOTPDevice{UserID: u.ID, Secret: "S", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	code := &models.RecoveryCode{UserID: u.ID, CodeHash: "h1"}
	if err := db.Create(code).Error; err != nil {
		t.Fatal(err)
	}

	if err := repo.MarkRecoveryCodeUsed(ctx, code); err != nil {
		t.Fatalf("first MarkRecoveryCodeUsed err=%v", err)
	}
	if err := repo.MarkRecoveryCodeUsed(ctx, code); !errors.Is(err, ErrRecoveryCodeUsed) {
		t.Fatalf("second MarkRecoveryCodeUsed must return ErrRecoveryCodeUsed, got %v", err)
	}
	var row models.RecoveryCode
	if err := db.First(&row, code.ID).Error; err != nil {
		t.Fatal(err)
	}
	if row.UsedAt == nil {
		t.Error("row must remain used after rejected second mark")
	}
}
