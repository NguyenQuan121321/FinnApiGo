package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/go-sql-driver/mysql"
)

// buildAuthService constructs an AuthService with fully configurable auth +
// rate-limit config and an injectable captcha verifier, for the hardening
// tests. All other deps are the standard in-memory mocks.
func buildAuthService(t *testing.T, cfg config.AuthConfig, rlCfg config.RateLimitConfig, captcha CaptchaVerifier) (
	*AuthService, *mockUserRepo, *mockTokenRepo, *mockAuditRepo, *mockNotifier, store.Store,
) {
	t.Helper()
	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	usedTokens := newMockUsedTokenRepo()
	store := newMockStore()
	audit := &mockAuditRepo{}
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	notify := &mockNotifier{}
	jwtCfg := config.JWTConfig{
		AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
		ResetTTL: 15 * time.Minute, VerifyTTL: time.Hour,
	}
	svc := NewAuthService(users, tokens, usedTokens, audit, store, jwtMgr, cfg, rlCfg, jwtCfg, notify, captcha, nil, nil, nil)
	return svc, users, tokens, audit, notify, store
}

// =====================================================================
// §2 — registration velocity limiting (per-IP)
// =====================================================================

func TestRegister_VelocityLimitPerIP(t *testing.T) {
	cfg := config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: 15 * time.Minute}
	rlCfg := config.RateLimitConfig{RegisterPerIPMax: 2, RegisterWindow: time.Hour}
	svc, _, _, _, _, _ := buildAuthService(t, cfg, rlCfg, nil)

	// First 2 from the same IP succeed.
	for i := 0; i < 2; i++ {
		_, err := svc.Register(context.Background(), RegisterInput{
			Username: "u" + strings.Repeat("x", i+1), Email: "u" + strings.Repeat("x", i+1) + "@e.com",
			Password: "Password1", FullName: "U", IP: "1.2.3.4",
		})
		if err != nil {
			t.Fatalf("register %d should succeed, got %v", i, err)
		}
	}
	// 3rd from the same IP is blocked.
	_, err := svc.Register(context.Background(), RegisterInput{
		Username: "u3", Email: "u3@e.com", Password: "Password1", FullName: "U", IP: "1.2.3.4",
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited on 3rd register from same IP, got %v", err)
	}
}

// =====================================================================
// §3 — per-account login velocity limit
// =====================================================================

func TestLogin_PerAccountVelocityLimit(t *testing.T) {
	cfg := config.AuthConfig{MaxLoginAttempts: 100, LoginLockoutDuration: 15 * time.Minute}
	rlCfg := config.RateLimitConfig{LoginPerAccountMax: 3, LoginWindow: time.Minute}
	svc, users, _, _, _, _ := buildAuthService(t, cfg, rlCfg, nil)
	// Seed a user with a known password directly (bypass Register's velocity).
	_ = users.Create(context.Background(), &models.User{
		ID: 1, Username: "alice", Email: "alice@example.com",
		Password: mustHash("Password1"), IsActive: true,
	})

	// 3 wrong-password attempts against the SAME account (different IPs) are OK.
	for i := 0; i < 3; i++ {
		_, _, _, _ = svc.Login(context.Background(), LoginInput{
			Email: "alice@example.com", Password: "wrong",
		}, "10.0.0."+itoa(i), "ua")
	}
	// 4th attempt against the same account is throttled regardless of IP.
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "99.99.99.99", "ua")
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited after per-account cap, got %v", err)
	}
}

// =====================================================================
// §3 — adaptive CAPTCHA after N failed logins from an IP
// =====================================================================

func TestLogin_AdaptiveCaptchaAfterFails(t *testing.T) {
	cfg := config.AuthConfig{MaxLoginAttempts: 100, LoginLockoutDuration: 15 * time.Minute}
	rlCfg := config.RateLimitConfig{
		LoginPerAccountMax:     10000, // high so per-account limiter doesn't interfere
		LoginCaptchaAfterFails: 2,
	}
	// Captcha verifier that REJECTS (simulating a missing/invalid token).
	captcha := &mockCaptchaVerifier{err: ErrCaptchaRejected}
	svc, users, _, _, _, _ := buildAuthService(t, cfg, rlCfg, captcha)
	_ = users.Create(context.Background(), &models.User{
		ID: 1, Username: "alice", Email: "alice@example.com",
		Password: mustHash("Password1"), IsActive: true,
	})

	// Two failures from the same IP cross the threshold.
	_, _, _, _ = svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "x"}, "5.5.5.5", "ua")
	_, _, _, _ = svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "x"}, "5.5.5.5", "ua")
	// Now the 3rd attempt from that IP must supply a valid CAPTCHA. Since our
	// mock rejects, we expect ErrCaptchaRequired (not ErrInvalidCredentials).
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1", CaptchaToken: "bad",
	}, "5.5.5.5", "ua")
	if !errors.Is(err, ErrCaptchaRequired) {
		t.Errorf("expected ErrCaptchaRequired after threshold, got %v", err)
	}
	if captcha.calls != 1 {
		t.Errorf("captcha verifier should have been called once, got %d", captcha.calls)
	}
}

func TestLogin_AdaptiveCaptchaPassesWithValidToken(t *testing.T) {
	cfg := config.AuthConfig{MaxLoginAttempts: 100, LoginLockoutDuration: 15 * time.Minute}
	rlCfg := config.RateLimitConfig{
		LoginPerAccountMax:     10000,
		LoginCaptchaAfterFails: 1,
	}
	captcha := &mockCaptchaVerifier{err: nil} // accepts
	svc, users, _, _, _, _ := buildAuthService(t, cfg, rlCfg, captcha)
	_ = users.Create(context.Background(), &models.User{
		ID: 1, Username: "alice", Email: "alice@example.com",
		Password: mustHash("Password1"), IsActive: true,
	})

	// One failure crosses the (low) threshold.
	_, _, _, _ = svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "x"}, "7.7.7.7", "ua")
	// Now a valid captcha lets the correct password through.
	pair, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1", CaptchaToken: "good",
	}, "7.7.7.7", "ua")
	if err != nil {
		t.Fatalf("expected success with valid captcha, got %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("expected an access token on successful login")
	}
}

// =====================================================================
// §3 — exponential lockout backoff for repeat offenders
// =====================================================================

func TestLogin_ExponentialLockoutBackoff(t *testing.T) {
	cfg := config.AuthConfig{
		MaxLoginAttempts:     2, // lock after 2 fails (fast for the test)
		LoginLockoutDuration: 10 * time.Minute,
		MaxLockoutMultiplier: 4,
	}
	rlCfg := config.RateLimitConfig{LoginPerAccountMax: 10000}
	svc, users, _, _, _, _ := buildAuthService(t, cfg, rlCfg, nil)
	_ = users.Create(context.Background(), &models.User{
		ID: 1, Username: "alice", Email: "alice@example.com",
		Password: mustHash("Password1"), IsActive: true,
	})

	// First lockout cycle: 2 failures → locked ~10 min (1× base).
	failTwice(svc, "alice@example.com")
	u1, _ := users.FindByID(context.Background(), 1)
	if u1.LockedUntil == nil {
		t.Fatal("expected first lockout")
	}
	firstLock := *u1.LockedUntil

	// Simulate the first lockout expiring so a new cycle can begin.
	clearLock(users, 1)

	// Second lockout cycle: 2 more failures → locked ~20 min (2× base).
	failTwice(svc, "alice@example.com")
	u2, _ := users.FindByID(context.Background(), 1)
	if u2.LockedUntil == nil {
		t.Fatal("expected second lockout")
	}
	// The second lockout must be strictly longer than the first.
	// With base=10m: 1st=10m, 2nd=20m → gap≈10m ≥ base.
	gap := u2.LockedUntil.Sub(firstLock)
	if gap < cfg.LoginLockoutDuration {
		t.Errorf("expected 2nd lockout gap ≥ base (%v); got gap=%v", cfg.LoginLockoutDuration, gap)
	}
}

// =====================================================================
// §2 — RequireEmailVerified login gate
// =====================================================================

func TestLogin_RequireEmailVerified(t *testing.T) {
	cfg := config.AuthConfig{
		MaxLoginAttempts:     5,
		LoginLockoutDuration: 15 * time.Minute,
		RequireEmailVerified: true,
	}
	rlCfg := config.RateLimitConfig{LoginPerAccountMax: 10000}
	svc, users, _, _, _, _ := buildAuthService(t, cfg, rlCfg, nil)
	// Seed an UNVERIFIED user.
	_ = users.Create(context.Background(), &models.User{
		ID: 1, Username: "alice", Email: "alice@example.com",
		Password: mustHash("Password1"), IsActive: true, IsEmailVerified: false,
	})

	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip", "ua")
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("expected ErrEmailNotVerified, got %v", err)
	}

	// Verify the email and retry — should now succeed.
	u, _ := users.FindByID(context.Background(), 1)
	_ = users.SetEmailVerified(context.Background(), u, true)
	_, _, _, err = svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip", "ua")
	if err != nil {
		t.Errorf("expected success after verification, got %v", err)
	}
}

// =====================================================================
// §1.7 — duplicate-key error mapping (errors.As *mysql.MySQLError)
// =====================================================================

func TestMapDuplicateKey_EmailFromMySQLError(t *testing.T) {
	// A real MySQL 1062 error whose message references the email index.
	dup := &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'a@b.com' for key 'users.email'"}
	err := mapDuplicateKey("a@b.com", "alice", dup)
	if !errors.Is(err, ErrEmailExists) {
		t.Errorf("expected ErrEmailExists, got %v", err)
	}
}

func TestMapDuplicateKey_UsernameFromMySQLError(t *testing.T) {
	dup := &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'alice' for key 'users.username'"}
	err := mapDuplicateKey("a@b.com", "alice", dup)
	if !errors.Is(err, ErrUsernameExists) {
		t.Errorf("expected ErrUsernameExists, got %v", err)
	}
}

func TestMapDuplicateKey_NonDuplicateWraps(t *testing.T) {
	// A non-duplicate error must NOT be mapped to a sentinel.
	other := errors.New("connection refused")
	err := mapDuplicateKey("a@b.com", "alice", other)
	if errors.Is(err, ErrEmailExists) || errors.Is(err, ErrUsernameExists) {
		t.Errorf("non-duplicate error must not map to a sentinel, got %v", err)
	}
}

func TestIsMySQLDup_UsesErrorsAs(t *testing.T) {
	// Direct *mysql.MySQLError.
	if !isMySQLDup(&mysql.MySQLError{Number: 1062, Message: "x"}) {
		t.Error("1062 error should be detected as duplicate")
	}
	// Wrapped once (fmt.Errorf %w) — errors.As must still see it.
	wrapped := wrapErr(&mysql.MySQLError{Number: 1062, Message: "x"})
	if !isMySQLDup(wrapped) {
		t.Error("wrapped 1062 error should be detected as duplicate")
	}
	// Non-1062 MySQL error is not a duplicate.
	if isMySQLDup(&mysql.MySQLError{Number: 1045, Message: "access denied"}) {
		t.Error("non-1062 MySQL error should not be a duplicate")
	}
	// Non-MySQL error is not a duplicate.
	if isMySQLDup(errors.New("something else")) {
		t.Error("non-MySQL error should not be a duplicate")
	}
}

// =====================================================================
// helpers
// =====================================================================

func mustHash(pw string) string {
	h, err := hash.HashPassword(pw)
	if err != nil {
		panic(err)
	}
	return h
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func failTwice(svc *AuthService, email string) {
	for i := 0; i < 2; i++ {
		_, _, _, _ = svc.Login(context.Background(), LoginInput{Email: email, Password: "wrong"}, "ip", "ua")
	}
}

func clearLock(repo *mockUserRepo, id uint) {
	u, _ := repo.FindByID(context.Background(), id)
	if u != nil {
		u.LockedUntil = nil
		u.FailedLoginAttempts = 0
		_ = repo.Update(context.Background(), u)
	}
}

// wrapErr returns err wrapped once with %w, to exercise errors.As traversal.
func wrapErr(err error) error { return fmt.Errorf("outer: %w", err) }
