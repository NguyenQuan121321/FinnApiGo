package services

// SetPassword tests run the REAL AuthService against real GORM repositories
// backed by an in-memory SQLite database (same driver as the repository
// tests), so they cover the exact persistence path production uses:
// FindByID → UpdatePassword → audit row. The "already has a password" guard
// is the core security boundary of this endpoint and is proven here end to
// end, including that the old password keeps working after a rejected
// attempt.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
)

// newSQLiteAuthService wires the real AuthService to real GORM repositories
// over an in-memory SQLite DB (mirrors the repositories tests' testDB helper).
// store is nil — SetPassword never touches it, and Login skips its velocity
// limiter when nil so the happy paths stay undisturbed.
func newSQLiteAuthService(t *testing.T) (*AuthService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(
		repositories.NewUserRepository(db),
		repositories.NewRefreshTokenRepository(db),
		repositories.NewUsedTokenRepository(db),
		repositories.NewAuditRepository(db),
		nil, // store — see comment above
		jwt.NewJWTManager("test-secret", "test-issuer"),
		config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: 15 * time.Minute},
		config.RateLimitConfig{},
		config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour},
		nil, nil, nil, nil, nil,
	)
	return svc, db
}

// seedUser inserts a user the way the real flows do: password == "" for a
// Google-OAuth-only account, or a bcrypt hash for a password-registered one.
func seedUser(t *testing.T, db *gorm.DB, username, email, password string) *models.User {
	t.Helper()
	if password != "" {
		h, err := hash.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		password = h
	}
	u := &models.User{
		Username: username, Email: email, Password: password,
		Role: models.RoleUser, IsActive: true, IsEmailVerified: true,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func assertAuditCount(t *testing.T, db *gorm.DB, event string, userID uint, want int64) {
	t.Helper()
	var n int64
	if err := db.Model(&models.AuditLog{}).
		Where("event = ? AND user_id = ?", event, userID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("audit rows event=%s userID=%d: got %d, want %d", event, userID, n, want)
	}
}

func TestSetPassword_SuccessForOAuthOnlyAccount(t *testing.T) {
	svc, db := newSQLiteAuthService(t)
	u := seedUser(t, db, "gina", "gina@example.com", "") // Google-only account

	if err := svc.SetPassword(context.Background(), u.ID, "NewPassword1", "1.2.3.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var stored models.User
	if err := db.First(&stored, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Password == "" || stored.Password == "NewPassword1" {
		t.Fatalf("expected a bcrypt hash to be persisted, got %q", stored.Password)
	}
	if !hash.CheckPassword(stored.Password, "NewPassword1") {
		t.Error("stored hash does not verify against the new password")
	}

	// Subsequent password login must succeed with the newly set password.
	pair, _, mfa, err := svc.Login(context.Background(),
		LoginInput{Email: "gina@example.com", Password: "NewPassword1"}, "1.2.3.4", "test-agent")
	if err != nil || mfa != nil {
		t.Fatalf("login with new password: err=%v mfa=%v", err, mfa)
	}
	if pair.AccessToken == "" {
		t.Error("expected an access token from login")
	}

	// Audited as the DISTINCT password_set event — and never as a change.
	assertAuditCount(t, db, models.AuditEventPasswordSet, u.ID, 1)
	assertAuditCount(t, db, models.AuditEventPasswordChanged, u.ID, 0)
}

func TestSetPassword_RejectsAccountWithExistingPassword(t *testing.T) {
	svc, db := newSQLiteAuthService(t)
	u := seedUser(t, db, "bob", "bob@example.com", "OriginalPass1")

	var before models.User
	if err := db.First(&before, u.ID).Error; err != nil {
		t.Fatal(err)
	}

	err := svc.SetPassword(context.Background(), u.ID, "AttackerPass1", "9.9.9.9")
	if !errors.Is(err, ErrPasswordAlreadySet) {
		t.Fatalf("expected ErrPasswordAlreadySet, got %v", err)
	}

	// The existing hash must be byte-for-byte untouched...
	var after models.User
	if err := db.First(&after, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Password != before.Password {
		t.Fatal("existing password hash was modified despite conflict rejection")
	}

	// ...proven by logging in with the ORIGINAL password afterward.
	if _, _, _, err := svc.Login(context.Background(),
		LoginInput{Email: "bob@example.com", Password: "OriginalPass1"}, "9.9.9.9", "test-agent"); err != nil {
		t.Fatalf("old password must still work after a rejected set-password: %v", err)
	}

	// Rejected attempts must not be audited as a password_set event.
	assertAuditCount(t, db, models.AuditEventPasswordSet, u.ID, 0)
}

func TestSetPassword_RejectsWeakPassword(t *testing.T) {
	svc, db := newSQLiteAuthService(t)
	u := seedUser(t, db, "gina", "gina@example.com", "")

	// Same rejection set the existing Register/ChangePassword tests use —
	// the strength rules are shared, not reimplemented.
	for _, pw := range []string{"short1", "onlyletters", "12345678", ""} {
		err := svc.SetPassword(context.Background(), u.ID, pw, "1.2.3.4")
		if !errors.Is(err, ErrPasswordTooWeak) {
			t.Errorf("password %q: expected ErrPasswordTooWeak, got %v", pw, err)
		}
	}

	var stored models.User
	if err := db.First(&stored, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Password != "" {
		t.Errorf("weak attempts must not persist a password, got %q", stored.Password)
	}
	assertAuditCount(t, db, models.AuditEventPasswordSet, u.ID, 0)
}

func TestSetPassword_UnknownUser(t *testing.T) {
	svc, _ := newSQLiteAuthService(t)
	if err := svc.SetPassword(context.Background(), 4242, "Password1", "1.2.3.4"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}
