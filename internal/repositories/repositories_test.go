package repositories

// These repository tests use a private in-memory SQLite database for fast,
// isolated CRUD coverage. MySQL-specific duplicate error 1062 mapping is
// deliberately covered with fakes in services tests, not forced through SQLite.

import (
	"context"
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
	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.OtpCode{}, &models.AuditLog{}, &models.UsedToken{}); err != nil {
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

func TestOtpAndUsedTokenRepositories(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	u := testUser(t, db)
	otpRepo := NewOtpRepository(db)
	usedRepo := NewUsedTokenRepository(db)
	active := &models.OtpCode{UserID: u.ID, CodeHash: "a", Purpose: models.OTPPurposeLogin, ExpiresAt: time.Now().Add(time.Hour)}
	if err := otpRepo.Create(ctx, active); err != nil {
		t.Fatal(err)
	}
	if got, err := otpRepo.FindLatestActive(ctx, u.ID, models.OTPPurposeLogin); err != nil || got == nil {
		t.Fatalf("active=%+v err=%v", got, err)
	}
	if n, err := otpRepo.IncrementAttempts(ctx, active); err != nil || n != 1 {
		t.Fatalf("attempts=%d err=%v", n, err)
	}
	if err := otpRepo.MarkUsed(ctx, active); err != nil {
		t.Fatal(err)
	}
	if got, err := otpRepo.FindLatestActive(ctx, u.ID, models.OTPPurposeLogin); err != nil || got != nil {
		t.Fatalf("used=%+v err=%v", got, err)
	}
	if n, err := otpRepo.PurgeExpired(ctx, time.Now()); err != nil || n != 1 {
		t.Fatalf("purge=%d err=%v", n, err)
	}
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
	if n := repo.BatchInsert(ctx, []*models.AuditLog{{Event: models.AuditEventLogout}, {Event: models.AuditEventOTPSent}}); n != 2 {
		t.Fatalf("BatchInsert=%d", n)
	}
	var count int64
	if err := db.Model(&models.AuditLog{}).Count(&count).Error; err != nil || count != 3 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}
