package services

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
)

// newTestAuthService builds an AuthService wired to in-memory mocks. Lockout
// knobs are tuned short for test speed.
func newTestAuthService(opts ...AuthServiceOption) (*AuthService, *mockUserRepo, *mockTokenRepo, *mockAuditRepo, *mockNotifier) {
	tokens := newMockTokenRepo()
	svc, users, audit, notify, _ := newTestAuthServiceWithTokens(tokens, opts...)
	return svc, users, tokens, audit, notify
}

// newTestAuthServiceWithTokens is newTestAuthService with a caller-supplied
// RefreshTokenRepo, for concurrency tests that must control the read→revoke
// race window deterministically. It also returns the mock store so tests can
// flush it (single-use durability, C8).
func newTestAuthServiceWithTokens(tokens RefreshTokenRepo, opts ...AuthServiceOption) (*AuthService, *mockUserRepo, *mockAuditRepo, *mockNotifier, *mockStore) {
	users := newMockUserRepo()
	usedTokens := newMockUsedTokenRepo()
	kv := newMockStore()
	audit := &mockAuditRepo{}
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	notify := &mockNotifier{}
	cfg := config.AuthConfig{
		MaxLoginAttempts:     5,
		LoginLockoutDuration: 15 * time.Minute,
	}
	rateLimitCfg := config.RateLimitConfig{
		RPS:                      100,
		Burst:                    20,
		LoginPerAccountMax:       10000,       // generous default so existing behavioral
		LoginWindow:              time.Minute, // tests are unaffected by velocity
		RegisterPerIPMax:         10000,       // limiters; tight-limit tests build a
		RegisterWindow:           time.Hour,   // dedicated service.
		VerifyResendPerEmailMax:  10000,
		VerifyResendWindow:       time.Minute,
		VerifyResendGlobalMax:    10000,
		VerifyResendGlobalWindow: time.Minute,
		VerifyResendPerIPMax:     10000,
		VerifyResendPerIPWindow:  time.Minute,
		LoginCaptchaAfterFails:   10000,
	}
	jwtCfg := config.JWTConfig{
		AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
		ResetTTL: 15 * time.Minute, VerifyTTL: time.Hour,
	}
	svc := NewAuthService(users, tokens, usedTokens, audit, kv, jwtMgr, cfg, rateLimitCfg, jwtCfg, notify, nil, nil, nil, nil, opts...)
	return svc, users, audit, notify, kv
}

// ----- Register -----

func TestRegister_Success(t *testing.T) {
	svc, users, _, _, notify := newTestAuthService()
	profile, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.Username != "alice" {
		t.Errorf("username = %q", profile.Username)
	}
	// §1.1 — verification token delivered via notifier, NOT in response.
	if notify.lastVerify == "" {
		t.Error("expected a verification token to be sent via notifier")
	}
	u, _ := users.FindByEmail(context.Background(), "alice@example.com")
	if u == nil {
		t.Fatal("user not persisted")
		return
	}
	if u.Password == "Password1" {
		t.Error("password must be hashed, not stored in plaintext")
	}
	if !hash.CheckPassword(u.Password, "Password1") {
		t.Error("hashed password does not verify")
	}
}

func TestRegister_RejectsDuplicateEmail(t *testing.T) {
	svc, _, _, audit, notify := newTestAuthService()
	in := RegisterInput{Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "A"}
	if _, err := svc.Register(context.Background(), in); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	profile, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice2", Email: "alice@example.com", Password: "Password1", FullName: "A",
	})
	if err != nil {
		t.Fatalf("expected neutral 201 success (P0.1), got %v", err)
	}
	if profile.Email != "alice@example.com" || profile.Username != "alice2" {
		t.Errorf("unexpected profile returned: %+v", profile)
	}
	// Wait a moment for fire-and-forget alert goroutine
	time.Sleep(50 * time.Millisecond)
	if notify.alertCount() != 1 {
		t.Errorf("expected 1 duplicate alert to owner, got %d", notify.alertCount())
	}
	events := audit.byEvent(models.AuditEventRegisterDuplicate)
	if len(events) != 1 {
		t.Errorf("expected 1 register_duplicate audit event, got %d", len(events))
	}
}

func TestRegister_RejectsWeakPassword(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	cases := []string{"short", "onlyletters", "12345678", ""}
	for _, pw := range cases {
		_, err := svc.Register(context.Background(), RegisterInput{
			Username: "u", Email: "u@example.com", Password: pw, FullName: "U",
		})
		if !errors.Is(err, ErrPasswordTooWeak) {
			t.Errorf("password %q expected ErrPasswordTooWeak, got %v", pw, err)
		}
	}
}

func TestRegister_RejectsDisposableEmail(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	_, err := svc.Register(context.Background(), RegisterInput{
		Username: "bot", Email: "test@mailinator.com", Password: "Password1", FullName: "Bot",
	})
	if !errors.Is(err, ErrDisposableEmail) {
		t.Errorf("expected ErrDisposableEmail, got %v", err)
	}
}

func TestRegister_PasswordLengthCap(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	longPw := string(make([]byte, 129)) // exceeds 128-char cap
	for i := range longPw {
		if i%10 == 0 {
			longPw = longPw[:i] + "a" + longPw[i+1:]
		}
	}
	longPw += "1" // ensure has letter + number
	_, err := svc.Register(context.Background(), RegisterInput{
		Username: "user", Email: "user@example.com", Password: longPw, FullName: "U",
	})
	if !errors.Is(err, ErrPasswordTooWeak) {
		t.Errorf("expected ErrPasswordTooWeak for 129-char password, got %v", err)
	}
}

// ----- Login -----

func TestLogin_Success(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	pair, profile, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("expected both tokens to be issued")
	}
	if profile.Email != "alice@example.com" {
		t.Errorf("profile email = %q", profile.Email)
	}
}

func TestLogin_WrongPassword_NoLockoutYet(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "wrong",
	}, "1.2.3.4", "test-agent")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	u, _ := users.FindByEmail(context.Background(), "alice@example.com")
	if u.FailedLoginAttempts != 1 {
		t.Errorf("failed attempts = %d, want 1", u.FailedLoginAttempts)
	}
	if u.LockedUntil != nil {
		t.Error("account should not be locked after a single failure")
	}
}

func TestLogin_LocksAfterMaxAttempts(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _, _, _ = svc.Login(context.Background(), LoginInput{
			Email: "alice@example.com", Password: "wrong",
		}, "1.2.3.4", "test-agent")
	}
	u, _ := users.FindByEmail(context.Background(), "alice@example.com")
	if u.LockedUntil == nil {
		t.Fatal("account should be locked after 5 failed attempts")
	}
	// Now even the correct password is rejected because of the lock.
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "test-agent")
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestLogin_UnknownUserDoesNotDistinguish(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "ghost@example.com", Password: "Password1",
	}, "1.2.3.4", "test-agent")
	// Must return the SAME error as a wrong password, to prevent enumeration.
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}

func TestLogin_AuditFailedRecordsEmail(t *testing.T) {
	svc, _, _, audit, _ := newTestAuthService()
	_, _, _, _ = svc.Login(context.Background(), LoginInput{
		Email: "ghost@example.com", Password: "bad",
	}, "10.0.0.1", "test-agent")
	events := audit.byEvent("login_failed")
	if len(events) == 0 {
		t.Fatal("expected a login_failed audit event")
	}
	if events[0].Email != "ghost@example.com" {
		t.Errorf("audit email = %q, want %q", events[0].Email, "ghost@example.com")
	}
	if events[0].IPAddress != "10.0.0.1" {
		t.Errorf("audit ip = %q, want %q", events[0].IPAddress, "10.0.0.1")
	}
}

// ----- Refresh (rotation) -----

func TestRefresh_RotatesAndInvalidatesOldToken(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	first, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Refresh(context.Background(), first.RefreshToken, "ip", "test-agent")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token must be rotated (new value expected)")
	}
	// Reusing the old token must now fail.
	_, err = svc.Refresh(context.Background(), first.RefreshToken, "ip", "test-agent")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on replay, got %v", err)
	}
}

func TestRefresh_ReuseDetection_RevokesAll(t *testing.T) {
	svc, _, _, audit, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	pair, _, _, _ := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip", "test-agent")
	// First refresh rotates to a new token.
	first, err := svc.Refresh(context.Background(), pair.RefreshToken, "ip", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	// Present the OLD (now revoked) token again — theft signal.
	_, err = svc.Refresh(context.Background(), pair.RefreshToken, "evil-ip", "evil-agent")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for reused token, got %v", err)
	}
	// The NEW token should also be revoked (revoke-all).
	_, err = svc.Refresh(context.Background(), first.RefreshToken, "ip", "test-agent")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken after revoke-all, got %v", err)
	}
	// A token_reuse audit event must have been recorded.
	events := audit.byEvent("token_reuse")
	if len(events) == 0 {
		t.Fatal("expected a token_reuse audit event")
	}
	if events[0].Detail != "revoked refresh token presented" {
		t.Errorf("detail = %q", events[0].Detail)
	}
}

// barrierTokenRepo holds every concurrent FindByHash call for one target hash
// until all racers have READ their clone, then releases them together — each
// racer is thereby guaranteed a pre-revoke copy of the token row. It
// reproduces the read→revoke TOCTOU window deterministically instead of
// relying on scheduler luck.
type barrierTokenRepo struct {
	*mockTokenRepo
	target   string
	racers   int32
	arrived  int32
	released chan struct{}
}

func (b *barrierTokenRepo) FindByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	rt, err := b.mockTokenRepo.FindByHash(ctx, hash)
	if hash == b.target && atomic.AddInt32(&b.arrived, 1) <= b.racers {
		if atomic.LoadInt32(&b.arrived) == b.racers {
			close(b.released)
		}
		<-b.released
	}
	return rt, err
}

// TestRefresh_ConcurrentDoubleRefresh_ExactlyOneSuccess_C1 — C1 regression:
// concurrent refreshes presenting the SAME token must yield exactly one
// success; every loser must be rejected as reuse (which also triggers
// revoke-all). The barrier guarantees every racer reads the token as
// un-revoked, which before the CAS fix made ALL of them rotate successfully.
func TestRefresh_ConcurrentDoubleRefresh_ExactlyOneSuccess_C1(t *testing.T) {
	inner := newMockTokenRepo()
	tokens := &barrierTokenRepo{mockTokenRepo: inner, racers: 8, released: make(chan struct{})}
	svc, _, audit, _, _ := newTestAuthServiceWithTokens(tokens)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	pair, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	// Login itself called FindByHash? No — but Refresh does; arm the barrier to
	// the token issued by Login now that its hash is computable.
	tokens.target = hash.HashToken(pair.RefreshToken)

	const racers = 8
	var wg sync.WaitGroup
	var successes atomic.Int32
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := svc.Refresh(context.Background(), pair.RefreshToken, "ip", "test-agent"); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("exactly one concurrent refresh must succeed, got %d/%d", got, racers)
	}
	// The losers' reuse handling must be observable: token_reuse audits and a
	// fully revoked session set (the winner's fresh token is dead too).
	if events := audit.byEvent("token_reuse"); len(events) == 0 {
		t.Error("expected token_reuse audit events from the losing racers")
	}
	_, err = svc.Refresh(context.Background(), pair.RefreshToken, "ip", "test-agent")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken after revoke-all, got %v", err)
	}
}

// ----- Forgot / reset password -----

func TestForgotPassword_UnknownEmailReturnsNil(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	if err := svc.ForgotPassword(context.Background(), "ghost@example.com", "ip"); err != nil {
		t.Errorf("unknown email must not error, got %v", err)
	}
	if notify.lastReset != "" {
		t.Error("no reset token should be generated for unknown email")
	}
}

func TestResetPassword_EndToEnd(t *testing.T) {
	svc, users, _, _, notify := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ForgotPassword(context.Background(), "alice@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	resetToken := notify.lastReset
	if resetToken == "" {
		t.Fatal("expected a reset token to be generated")
	}
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: resetToken, NewPassword: "NewPassword2",
	}, "ip"); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	u, _ := users.FindByEmail(context.Background(), "alice@example.com")
	if !hash.CheckPassword(u.Password, "NewPassword2") {
		t.Error("new password did not take effect")
	}
}

func TestResetPassword_SingleUseToken(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	_ = svc.ForgotPassword(context.Background(), "alice@example.com", "ip")
	resetToken := notify.lastReset

	// First use succeeds.
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: resetToken, NewPassword: "NewPassword2",
	}, "ip"); err != nil {
		t.Fatalf("first reset should succeed: %v", err)
	}
	// Second use must fail (single-use via jti).
	err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: resetToken, NewPassword: "ThirdPassword3",
	}, "ip")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on replay, got %v", err)
	}
}

// ----- Change password -----

func TestChangePassword_RequiresCorrectOldPassword(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService()
	_, _ = svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	uid := uint(1)
	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: uid, OldPassword: "wrong", NewPassword: "NewPassword2",
	}, "ip")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	// correct old password
	if err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: uid, OldPassword: "Password1", NewPassword: "NewPassword2",
	}, "ip"); err != nil {
		t.Fatalf("change failed: %v", err)
	}
	u, _ := users.FindByID(context.Background(), uid)
	if !hash.CheckPassword(u.Password, "NewPassword2") {
		t.Error("password not updated")
	}
}

// ----- Verify email -----

func TestVerifyEmail(t *testing.T) {
	svc, users, _, _, notify := newTestAuthService()
	_, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyToken := notify.lastVerify
	if err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: verifyToken}); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	u, _ := users.FindByEmail(context.Background(), "alice@example.com")
	if !u.IsEmailVerified {
		t.Error("email should be marked verified")
	}
}

func TestVerifyEmail_RejectsAccessToken(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	profile, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	access, _ := jwtMgr.Issue(profile.ID, "user", profile.Email, jwt.TokenTypeAccess, time.Minute)
	err = svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: access})
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken when passing an access token, got %v", err)
	}
}

func TestVerifyEmail_SingleUseToken(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	_, _ = svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	verifyToken := notify.lastVerify

	// First use succeeds.
	if err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: verifyToken}); err != nil {
		t.Fatalf("first verify should succeed: %v", err)
	}
	// Second use must fail (single-use via jti).
	err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: verifyToken})
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on replay, got %v", err)
	}
}

// ----- Resend verification email -----

func TestResendVerifyEmail_SendsFreshToken(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	firstToken := notify.lastVerify
	if firstToken == "" {
		t.Fatal("register should have sent a verification token")
	}

	if err := svc.ResendVerifyEmail(context.Background(), "alice@example.com", "ip"); err != nil {
		t.Fatalf("resend failed: %v", err)
	}
	secondToken := notify.lastVerify
	if secondToken == "" || secondToken == firstToken {
		t.Fatal("resend should issue a distinct fresh token")
	}

	// The fresh token must be consumable by VerifyEmail (round-trips to verified).
	if err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: secondToken}); err != nil {
		t.Fatalf("verify with resent token failed: %v", err)
	}
}

func TestResendVerifyEmail_UnknownEmailReturnsNil(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	if err := svc.ResendVerifyEmail(context.Background(), "ghost@example.com", "ip"); err != nil {
		t.Errorf("unknown email must not error (anti-enumeration), got %v", err)
	}
	if notify.lastVerify != "" {
		t.Error("no verification token should be generated for an unknown email")
	}
}

func TestResendVerifyEmail_AlreadyVerifiedIsNoOp(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	// Consume the registration token to mark the account verified.
	if err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: notify.lastVerify}); err != nil {
		t.Fatal(err)
	}
	notify.lastVerify = "" // reset so we can detect a new send

	if err := svc.ResendVerifyEmail(context.Background(), "alice@example.com", "ip"); err != nil {
		t.Fatalf("resend for a verified account should be a no-op (nil), got %v", err)
	}
	if notify.lastVerify != "" {
		t.Error("no verification email should be sent for an already-verified account")
	}
}

func TestResendVerifyEmail_RateLimited(t *testing.T) {
	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	usedTokens := newMockUsedTokenRepo()
	store := newMockStore()
	audit := &mockAuditRepo{}
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	notify := &mockNotifier{}
	rlCfg := config.RateLimitConfig{
		VerifyResendPerEmailMax: 1, // tight limit
		VerifyResendWindow:      time.Minute,
	}
	svc := NewAuthService(users, tokens, usedTokens, audit, store, jwtMgr,
		config.AuthConfig{}, rlCfg, config.JWTConfig{VerifyTTL: time.Hour}, notify, nil, nil, nil, nil)

	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}

	// First resend within the limit.
	if err := svc.ResendVerifyEmail(context.Background(), "alice@example.com", "ip"); err != nil {
		t.Fatalf("first resend should succeed, got %v", err)
	}
	// Second resend must be throttled.
	err := svc.ResendVerifyEmail(context.Background(), "alice@example.com", "ip")
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited on second resend, got %v", err)
	}
}

func TestResendVerifyEmail_NotifierErrorPropagates(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	notify.verifySendErr = errors.New("smtp down")

	err := svc.ResendVerifyEmail(context.Background(), "alice@example.com", "ip")
	if err == nil {
		t.Fatal("expected an error when the notifier fails")
	}
	if errors.Is(err, ErrRateLimited) {
		t.Errorf("notifier failure must not be masked as ErrRateLimited, got %v", err)
	}
	if !strings.Contains(err.Error(), "resend-verify") {
		t.Errorf("expected wrapped resend-verify error, got %v", err)
	}
}

// newResendTestService builds an AuthService with a custom RateLimitConfig and
// the supplied mocks, so each hardening test can tighten exactly one layer
// while leaving the others disabled (max=0 => disabled by the > 0 guard).
func newResendTestService(rlCfg config.RateLimitConfig, users *mockUserRepo, audit *mockAuditRepo, notify *mockNotifier) *AuthService {
	return NewAuthService(
		users, newMockTokenRepo(), newMockUsedTokenRepo(), audit, newMockStore(),
		jwt.NewJWTManager("test-secret", "test-issuer"),
		config.AuthConfig{}, rlCfg,
		config.JWTConfig{VerifyTTL: time.Hour}, notify, nil, nil, nil, nil,
	)
}

func TestResendVerifyEmail_GlobalCap(t *testing.T) {
	users := newMockUserRepo()
	audit := &mockAuditRepo{}
	notify := &mockNotifier{}
	// Global cap = 1: only ONE resend across ALL emails+IPs per window. Other
	// layers disabled (0). This proves the cap defeats unique-email flooding.
	svc := newResendTestService(config.RateLimitConfig{
		VerifyResendGlobalMax:    1,
		VerifyResendGlobalWindow: time.Minute,
	}, users, audit, notify)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "bob", Email: "bob@example.com", Password: "Password1", FullName: "Bob",
	}); err != nil {
		t.Fatal(err)
	}

	// First resend (alice) consumes the single global slot.
	if err := svc.ResendVerifyEmail(context.Background(), "alice@example.com", "1.1.1.1"); err != nil {
		t.Fatalf("first resend should succeed, got %v", err)
	}
	// Second resend (DIFFERENT email + IP) must still trip the global cap.
	err := svc.ResendVerifyEmail(context.Background(), "bob@example.com", "2.2.2.2")
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited from global cap on different email/IP, got %v", err)
	}
}

func TestResendVerifyEmail_PerIPCap(t *testing.T) {
	users := newMockUserRepo()
	audit := &mockAuditRepo{}
	notify := &mockNotifier{}
	svc := newResendTestService(config.RateLimitConfig{
		VerifyResendPerIPMax:    1,
		VerifyResendPerIPWindow: time.Minute,
	}, users, audit, notify)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "bob", Email: "bob@example.com", Password: "Password1", FullName: "Bob",
	}); err != nil {
		t.Fatal(err)
	}

	// First resend from this IP succeeds.
	if err := svc.ResendVerifyEmail(context.Background(), "alice@example.com", "9.9.9.9"); err != nil {
		t.Fatalf("first resend should succeed, got %v", err)
	}
	// Second resend from the SAME IP (different email) must be throttled.
	err := svc.ResendVerifyEmail(context.Background(), "bob@example.com", "9.9.9.9")
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited from per-IP cap, got %v", err)
	}
}

func TestResendVerifyEmail_DisposableDomainSwallowed(t *testing.T) {
	svc, _, _, _, notify := newTestAuthService()
	// Disposable domain must be swallowed as success-like (anti-enumeration)
	// and must NOT trigger any email send.
	err := svc.ResendVerifyEmail(context.Background(), "spammer@mailinator.com", "1.2.3.4")
	if err != nil {
		t.Errorf("disposable email must not surface an error (anti-enumeration), got %v", err)
	}
	if notify.lastVerify != "" {
		t.Error("no verification email should be sent for a disposable domain")
	}
}

func TestResendVerifyEmail_GlobalCapRecordsAudit(t *testing.T) {
	users := newMockUserRepo()
	audit := &mockAuditRepo{}
	notify := &mockNotifier{}
	svc := newResendTestService(config.RateLimitConfig{
		VerifyResendGlobalMax:    1,
		VerifyResendGlobalWindow: time.Minute,
	}, users, audit, notify)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}

	_ = svc.ResendVerifyEmail(context.Background(), "alice@example.com", "1.1.1.1")
	_ = svc.ResendVerifyEmail(context.Background(), "alice@example.com", "1.1.1.1") // trips global cap

	blocked := audit.byEvent(models.AuditEventVerifyResendBlocked)
	if len(blocked) == 0 {
		t.Fatal("expected an audit entry for the global-cap block")
	}
	if blocked[0].Detail != "global cap" {
		t.Errorf("expected detail 'global cap', got %q", blocked[0].Detail)
	}
}

func TestResendVerifyEmail_PerIPCapRecordsAudit(t *testing.T) {
	users := newMockUserRepo()
	audit := &mockAuditRepo{}
	notify := &mockNotifier{}
	svc := newResendTestService(config.RateLimitConfig{
		VerifyResendPerIPMax:    1,
		VerifyResendPerIPWindow: time.Minute,
	}, users, audit, notify)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}

	_ = svc.ResendVerifyEmail(context.Background(), "alice@example.com", "8.8.8.8")
	_ = svc.ResendVerifyEmail(context.Background(), "alice@example.com", "8.8.8.8") // trips per-IP cap

	blocked := audit.byEvent(models.AuditEventVerifyResendBlocked)
	if len(blocked) == 0 {
		t.Fatal("expected an audit entry for the per-IP block")
	}
	if blocked[0].Detail != "per-ip cap" {
		t.Errorf("expected detail 'per-ip cap', got %q", blocked[0].Detail)
	}
}

func TestResendVerifyEmail_DisposableRecordsAudit(t *testing.T) {
	users := newMockUserRepo()
	audit := &mockAuditRepo{}
	notify := &mockNotifier{}
	svc := newResendTestService(config.RateLimitConfig{}, users, audit, notify)

	_ = svc.ResendVerifyEmail(context.Background(), "spammer@mailinator.com", "5.5.5.5")

	blocked := audit.byEvent(models.AuditEventVerifyResendBlocked)
	if len(blocked) == 0 {
		t.Fatal("expected an audit entry for the disposable-domain rejection")
	}
	if blocked[0].Detail != "disposable domain" {
		t.Errorf("expected detail 'disposable domain', got %q", blocked[0].Detail)
	}
}

// ----- Logout all -----

func TestLogoutAll(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	_, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	uid := uint(1)
	if err := svc.LogoutAll(context.Background(), uid, "ip"); err != nil {
		t.Fatalf("LogoutAll failed: %v", err)
	}
	// All tokens should now be revoked — refresh must fail.
}

// ----- Session & Device Management -----

func TestListSessions_AfterLogin(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	// Login twice to create two sessions.
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
	if err != nil {
		t.Fatalf("login1: %v", err)
	}
	_, _, _, err = svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "5.6.7.8", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/605.1")
	if err != nil {
		t.Fatalf("login2: %v", err)
	}
	sessions, err := svc.ListSessions(context.Background(), 1, "")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("len(sessions)=%d, want 2", len(sessions))
	}
	// Most recently active first — the second login created the freshest session.
	if sessions[0].DeviceName != "Safari on iPhone" {
		t.Errorf("first session device = %q, want %q", sessions[0].DeviceName, "Safari on iPhone")
	}
	if sessions[0].LocationEstimate != "Unknown" {
		t.Errorf("default location should be Unknown, got %q", sessions[0].LocationEstimate)
	}
}

func TestListSessions_SkipsRevokedAndExpired(t *testing.T) {
	svc, _, tokens, _, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	// Login creates session id=1.
	_, _, _, _ = svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.1.1.1", "agent")
	// Manually revoke session 1 and add an expired row.
	tokens.mu.Lock()
	for _, rt := range tokens.rows {
		if rt.UserID == 1 {
			rt.Revoked = true
		}
	}
	expired := &models.RefreshToken{
		ID: 999, UserID: 1, TokenHash: "exp", Revoked: false,
		ExpiresAt: time.Now().Add(-time.Hour), LastActiveAt: time.Now().Add(-time.Hour),
		DeviceName: "old",
	}
	tokens.rows[999] = expired
	tokens.byHash["exp"] = 999
	tokens.mu.Unlock()

	sessions, err := svc.ListSessions(context.Background(), 1, "")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("len(sessions)=%d, want 0 (all revoked/expired)", len(sessions))
	}
}

func TestRevokeSession_Success(t *testing.T) {
	svc, _, _, audit, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "agent")
	// Revoke session id=1.
	if err := svc.RevokeSession(context.Background(), "1", 1, "10.0.0.1"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	// Verify it no longer appears in the active list.
	sessions, _ := svc.ListSessions(context.Background(), 1, "")
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions after revoke, got %d", len(sessions))
	}
	// Audit event must be recorded.
	events := audit.byEvent(models.AuditEventSessionRevoked)
	if len(events) != 1 {
		t.Fatalf("expected 1 session_revoked event, got %d", len(events))
	}
	if events[0].IPAddress != "10.0.0.1" {
		t.Errorf("audit ip = %q, want %q", events[0].IPAddress, "10.0.0.1")
	}
}

func TestRevokeSession_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	err := svc.RevokeSession(context.Background(), "9999", 1, "ip")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestRevokeSession_IDOR_WrongUser(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	// Register two users.
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "bob", Email: "bob@example.com", Password: "Password1", FullName: "Bob",
	}); err != nil {
		t.Fatal(err)
	}
	// Login alice (session belongs to user 1).
	_, _, _, _ = svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.1.1.1", "agent")
	// Bob tries to revoke alice's session → should get ErrSessionNotFound (scoped to bob's id=2).
	err := svc.RevokeSession(context.Background(), "1", 2, "evil")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound for cross-user revoke, got %v", err)
	}
}

func TestRefresh_MetadataPopulated(t *testing.T) {
	svc, _, tokens, _, _ := newTestAuthService()
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	pair, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "10.0.0.1", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	// Find the session row the login created.
	tokens.mu.Lock()
	var loginRT *models.RefreshToken
	for _, rt := range tokens.rows {
		if rt.UserID == 1 && !rt.Revoked {
			loginRT = rt
		}
	}
	tokens.mu.Unlock()
	if loginRT == nil {
		t.Fatal("no active session found after login")
		return
	}
	if loginRT.IPAddress != "10.0.0.1" {
		t.Errorf("ip = %q, want %q", loginRT.IPAddress, "10.0.0.1")
	}
	if loginRT.DeviceName != "Chrome on Windows" {
		t.Errorf("device = %q, want %q", loginRT.DeviceName, "Chrome on Windows")
	}
	if loginRT.LocationEstimate != "Unknown" {
		t.Errorf("location = %q, want %q", loginRT.LocationEstimate, "Unknown")
	}
	if loginRT.LastActiveAt.IsZero() {
		t.Error("LastActiveAt should be set")
	}
	// Refresh — the NEW session should carry the new caller's metadata.
	second, err := svc.Refresh(context.Background(), pair.RefreshToken, "20.0.0.2", "Mozilla/5.0 (iPhone) Safari/605.1")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	tokens.mu.Lock()
	var refreshRT *models.RefreshToken
	for _, rt := range tokens.rows {
		if rt.UserID == 1 && !rt.Revoked {
			refreshRT = rt
		}
	}
	tokens.mu.Unlock()
	if refreshRT == nil {
		t.Fatal("no active session found after refresh")
		return
	}
	if refreshRT.IPAddress != "20.0.0.2" {
		t.Errorf("refreshed session ip = %q, want %q", refreshRT.IPAddress, "20.0.0.2")
	}
	if refreshRT.DeviceName != "Safari on iPhone" {
		t.Errorf("refreshed session device = %q, want %q", refreshRT.DeviceName, "Safari on iPhone")
	}
	_ = second // consumed
}

func TestListSessions_WithCustomGeoResolver(t *testing.T) {
	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	usedTokens := newMockUsedTokenRepo()
	store := newMockStore()
	audit := &mockAuditRepo{}
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	notify := &mockNotifier{}
	geoResolver := mockGeoResolver{loc: "Berlin, DE"}

	svc := NewAuthService(users, tokens, usedTokens, audit, store, jwtMgr,
		config.AuthConfig{MaxLoginAttempts: 5},
		config.RateLimitConfig{},
		config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour},
		notify, nil, geoResolver, nil, nil,
	)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "Chrome/120.0")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	sessions, err := svc.ListSessions(context.Background(), 1, "")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len=%d, want 1", len(sessions))
	}
	if sessions[0].LocationEstimate != "Berlin, DE" {
		t.Errorf("location = %q, want %q", sessions[0].LocationEstimate, "Berlin, DE")
	}
}

// ----- MFA enforcement at login -----

func newMFATestAuthService() (*AuthService, *mockUserRepo, *mockTokenRepo, *mockTOTPRepo, *mockTOTPValidator) {
	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	usedTokens := newMockUsedTokenRepo()
	store := newMockStore()
	audit := &mockAuditRepo{}
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	notify := &mockNotifier{}
	totpRepo := newMockTOTPRepo()
	totpVal := &mockTOTPValidator{}

	cfg := config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: 15 * time.Minute}
	rlCfg := config.RateLimitConfig{
		LoginPerAccountMax: 10000, LoginWindow: time.Minute,
		LoginCaptchaAfterFails: 10000,
	}
	jwtCfg := config.JWTConfig{
		AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
		MFAPendingTTL: 5 * time.Minute,
	}
	svc := NewAuthService(users, tokens, usedTokens, audit, store, jwtMgr, cfg, rlCfg, jwtCfg, notify, nil, nil, totpRepo, totpVal)
	return svc, users, tokens, totpRepo, totpVal
}

func TestLogin_TOTPInactive_FullTokens(t *testing.T) {
	svc, _, tokens, _, _ := newMFATestAuthService()
	_, _ = svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	pair, profile, mfaPending, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mfaPending != nil {
		t.Fatal("mfaPending should be nil for user without TOTP")
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("expected both tokens to be issued")
	}
	if profile.Email != "alice@example.com" {
		t.Errorf("profile email = %q", profile.Email)
	}
	// Verify a RefreshToken DB record was created.
	tokens.mu.Lock()
	count := len(tokens.rows)
	tokens.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected 1 refresh token row, got %d", count)
	}
}

func TestLogin_TOTPActive_ReturnsMFAPending(t *testing.T) {
	svc, _, tokens, totpRepo, _ := newMFATestAuthService()
	_, _ = svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	// Simulate TOTP enabled for this user.
	totpRepo.mu.Lock()
	//nolint:gosec
	totpRepo.devices[1] = &models.TOTPDevice{ID: 1, UserID: 1, Secret: "JBSWY3DPEHPK3PXP", Enabled: true}
	totpRepo.mu.Unlock()
	// ... rest of test

	pair, _, mfaPending, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mfaPending == nil {
		t.Fatal("mfaPending should not be nil for TOTP-active user")
		return
	}
	if !mfaPending.MFARequired {
		t.Error("MFARequired should be true")
	}
	if mfaPending.MFAToken == "" {
		t.Error("MFAToken should not be empty")
	}
	// Verify the mfa_pending token is valid and carries the right type.
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	claims, err := jwtMgr.Verify(mfaPending.MFAToken)
	if err != nil {
		t.Fatalf("mfa token verification failed: %v", err)
	}
	if claims.Type != jwt.TokenTypeMFAPending {
		t.Errorf("token type = %q, want %q", claims.Type, jwt.TokenTypeMFAPending)
	}
	if claims.UserID != 1 {
		t.Errorf("token uid = %d, want 1", claims.UserID)
	}
	// No role or email should be in the mfa_pending token.
	if claims.Role != "" {
		t.Errorf("mfa_pending token should not carry role, got %q", claims.Role)
	}
	if claims.Email != "" {
		t.Errorf("mfa_pending token should not carry email, got %q", claims.Email)
	}
	// No real tokens should have been issued.
	if pair.AccessToken != "" || pair.RefreshToken != "" {
		t.Error("real tokens should not be issued when MFA is pending")
	}
	// No RefreshToken DB record should have been created.
	tokens.mu.Lock()
	count := len(tokens.rows)
	tokens.mu.Unlock()
	if count != 0 {
		t.Fatalf("expected 0 refresh token rows, got %d", count)
	}
}

func TestCompleteMFALogin_CorrectCode(t *testing.T) {
	svc, _, tokens, totpRepo, totpVal := newMFATestAuthService()
	_, _ = svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	totpRepo.mu.Lock()
	//nolint:gosec
	totpRepo.devices[1] = &models.TOTPDevice{ID: 1, UserID: 1, Secret: "JBSWY3DPEHPK3PXP", Enabled: true}
	totpRepo.mu.Unlock()
	// ... rest of test

	pair, profile, err := svc.CompleteMFALogin(context.Background(), CompleteMFALoginInput{
		UserID: 1, Code: "123456", IP: "1.2.3.4", UA: "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0",
	})
	if err != nil {
		t.Fatalf("CompleteMFALogin failed: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("expected both tokens")
	}
	if profile.Email != "alice@example.com" {
		t.Errorf("profile email = %q", profile.Email)
	}
	// Verify RefreshToken DB record was created with device metadata.
	tokens.mu.Lock()
	var rt *models.RefreshToken
	for _, row := range tokens.rows {
		if row.UserID == 1 && !row.Revoked {
			rt = row
		}
	}
	tokens.mu.Unlock()
	if rt == nil {
		t.Fatal("no refresh token record created")
		return
	}
	if rt.IPAddress != "1.2.3.4" {
		t.Errorf("rt IP = %q, want %q", rt.IPAddress, "1.2.3.4")
	}
	if rt.DeviceName == "" {
		t.Error("device name should be populated from user-agent")
	}
	// Verify the mock validator was actually called.
	if totpVal.calls != 1 {
		t.Errorf("expected 1 Validate call, got %d", totpVal.calls)
	}
}

func TestCompleteMFALogin_WrongCode(t *testing.T) {
	svc, _, _, totpRepo, totpVal := newMFATestAuthService()
	_, _ = svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	totpRepo.mu.Lock()
	//nolint:gosec
	totpRepo.devices[1] = &models.TOTPDevice{ID: 1, UserID: 1, Secret: "JBSWY3DPEHPK3PXP", Enabled: true}
	totpRepo.mu.Unlock()
	// ... rest of test

	// Set up mock to reject the code.
	totpVal.err = ErrInvalidCode

	_, _, err := svc.CompleteMFALogin(context.Background(), CompleteMFALoginInput{
		UserID: 1, Code: "000000", IP: "1.2.3.4", UA: "agent",
	})
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

// mockGeoResolver is a test geo.Resolver returning a fixed label.
type mockGeoResolver struct {
	loc string
}

func (m mockGeoResolver) Resolve(_ context.Context, _ string) string { return m.loc }

// TestResetPassword_SingleUse_SurvivesStoreFlush_C8 — C8 regression: the
// volatile store alone must not decide single-use. After a successful reset,
// flushing the store (Redis restart / eviction) must NOT revive the token —
// the durable used_tokens row rejects the replay.
func TestResetPassword_SingleUse_SurvivesStoreFlush_C8(t *testing.T) {
	svc, users, _, notify, kv := newTestAuthServiceWithTokens(newMockTokenRepo())
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ForgotPassword(context.Background(), "alice@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	in := ResetPasswordInput{Token: notify.lastReset, NewPassword: "NewPassword1"}
	if err := svc.ResetPassword(context.Background(), in, "ip"); err != nil {
		t.Fatalf("first reset failed: %v", err)
	}

	// Simulate a store flush — every jti marker gone.
	kv.mu.Lock()
	kv.data = map[string]any{}
	kv.mu.Unlock()

	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: notify.lastReset, NewPassword: "AttackerPassword1",
	}, "evil-ip"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("replay after store flush must be rejected, got %v", err)
	}
	u, _ := users.FindByEmail(context.Background(), "alice@example.com")
	if !hash.CheckPassword(u.Password, "NewPassword1") {
		t.Error("victim's password must be unchanged by the rejected replay")
	}
}

// TestVerifyEmail_SingleUse_SurvivesStoreFlush_C8 — same durability property
// for the verify-email token.
func TestVerifyEmail_SingleUse_SurvivesStoreFlush_C8(t *testing.T) {
	svc, _, _, notify, kv := newTestAuthServiceWithTokens(newMockTokenRepo())
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "bob", Email: "bob@example.com", Password: "Password1", FullName: "Bob",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: notify.lastVerify}); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}

	kv.mu.Lock()
	kv.data = map[string]any{}
	kv.mu.Unlock()

	if err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: notify.lastVerify}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("verify-email replay after store flush must be rejected, got %v", err)
	}
}

// TestLogin_SuccessClearsPerAccountCounter_C9 — C9 regression: a successful
// login must reset the per-account velocity counter so earlier typos don't
// linger toward the cap (pre-fix the counter counted EVERY attempt and never
// reset — fail/fail/success left the account one typo away from 429).
func TestLogin_SuccessClearsPerAccountCounter_C9(t *testing.T) {
	cfg := config.AuthConfig{MaxLoginAttempts: 50, LoginLockoutDuration: time.Minute}
	rlCfg := config.RateLimitConfig{LoginPerAccountMax: 3, LoginWindow: time.Hour}
	svc, _, _, _, _, _ := buildAuthService(t, cfg, rlCfg, nil)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "carol", Email: "carol@example.com", Password: "Password1", FullName: "C",
	}); err != nil {
		t.Fatal(err)
	}

	// Two failures below the cap...
	for i := 0; i < 2; i++ {
		_, _, _, err := svc.Login(context.Background(), LoginInput{
			Email: "carol@example.com", Password: "WrongPass1",
		}, "ip", "ua")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failed login %d: %v", i, err)
		}
	}
	// ...then the correct password: the success must CLEAR the counter.
	if _, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "carol@example.com", Password: "Password1",
	}, "ip", "ua"); err != nil {
		t.Fatalf("correct login after typos must succeed, got %v", err)
	}

	// The window restarted: three more wrong attempts are ordinary credential
	// failures (pre-fix the lingering counter 429'd the first of them)...
	for i := 0; i < 3; i++ {
		_, _, _, err := svc.Login(context.Background(), LoginInput{
			Email: "carol@example.com", Password: "WrongPass1",
		}, "ip", "ua")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("post-reset wrong login %d must be ErrInvalidCredentials, got %v", i, err)
		}
	}
	// ...and only the attempt after the fresh batch trips the cap.
	_, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "carol@example.com", Password: "WrongPass1",
	}, "ip", "ua")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("attempt after cap must be ErrRateLimited, got %v", err)
	}
}

// TestResetPassword_ClearsLockoutState_C10 — C10 regression: resetting the
// password must clear the attacker-sustained lockout, else the victim resets
// and STILL cannot log in.
func TestResetPassword_ClearsLockoutState_C10(t *testing.T) {
	svc, users, _, notify, _ := newTestAuthServiceWithTokens(newMockTokenRepo())
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "dave", Email: "dave@example.com", Password: "Password1", FullName: "D",
	}); err != nil {
		t.Fatal(err)
	}
	// Attacker-sustained lockout: attempts racked up, account locked for an hour.
	u, _ := users.FindByEmail(context.Background(), "dave@example.com")
	lock := time.Now().Add(time.Hour)
	for i := 0; i < 5; i++ {
		if err := users.IncrementFailedAttempts(context.Background(), u, &lock); err != nil {
			t.Fatal(err)
		}
	}

	if err := svc.ForgotPassword(context.Background(), "dave@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: notify.lastReset, NewPassword: "FreshPassword1",
	}, "ip"); err != nil {
		t.Fatal(err)
	}

	got, _ := users.FindByEmail(context.Background(), "dave@example.com")
	if got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
		t.Fatalf("lockout must be cleared by reset: attempts=%d locked_until=%v",
			got.FailedLoginAttempts, got.LockedUntil)
	}
	// The victim can log in immediately with the new password.
	if _, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "dave@example.com", Password: "FreshPassword1",
	}, "ip", "ua"); err != nil {
		t.Fatalf("login after reset must not be locked, got %v", err)
	}
}

// TestChangePassword_ClearsLockoutState_C10 — same invariant for the
// authenticated change-password flow.
func TestChangePassword_ClearsLockoutState_C10(t *testing.T) {
	svc, users, _, _, _ := newTestAuthServiceWithTokens(newMockTokenRepo())
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "erin", Email: "erin@example.com", Password: "Password1", FullName: "E",
	}); err != nil {
		t.Fatal(err)
	}
	u, _ := users.FindByEmail(context.Background(), "erin@example.com")
	lock := time.Now().Add(time.Hour)
	for i := 0; i < 5; i++ {
		if err := users.IncrementFailedAttempts(context.Background(), u, &lock); err != nil {
			t.Fatal(err)
		}
	}

	if err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: u.ID, OldPassword: "Password1", NewPassword: "FreshPassword1",
	}, "ip"); err != nil {
		t.Fatal(err)
	}

	got, _ := users.FindByID(context.Background(), u.ID)
	if got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
		t.Fatalf("lockout must be cleared by change: attempts=%d locked_until=%v",
			got.FailedLoginAttempts, got.LockedUntil)
	}
}

// TestRegister_NotifierFailureStillSucceeds_C11 — C11 regression: the user
// row is already committed when the verification email send fails; returning
// 500 made the client retry into ErrEmailExists. A delivery failure is now
// a successful registration + error log + audit (the resend endpoint exists).
func TestRegister_NotifierFailureStillSucceeds_C11(t *testing.T) {
	svc, users, _, audit, notify := newTestAuthService()
	notify.mu.Lock()
	notify.verifySendErr = errors.New("smtp down")
	notify.mu.Unlock()

	profile, err := svc.Register(context.Background(), RegisterInput{
		Username: "frank", Email: "frank@example.com", Password: "Password1", FullName: "F",
	})
	if err != nil {
		t.Fatalf("register must succeed despite notifier failure, got %v", err)
	}
	if profile.Username != "frank" {
		t.Errorf("profile = %+v", profile)
	}
	if u, _ := users.FindByEmail(context.Background(), "frank@example.com"); u == nil {
		t.Fatal("user row must exist")
	}
	if events := audit.byEvent("verify_email_send_failed"); len(events) != 1 {
		t.Fatalf("expected one verify_email_send_failed audit event, got %d", len(events))
	}
}

// failingStore models a store whose backend is down, per the A1 contract:
// counters fail open (IncrBy → 0, Get → absent) while single-use guards fail
// closed (SetNX → false).
type failingStore struct{}

func (failingStore) Get(string) (any, bool)                    { return nil, false }
func (failingStore) Take(string) (any, bool)                   { return nil, false }
func (failingStore) Set(string, any, time.Duration)            {}
func (failingStore) SetNX(string, any, time.Duration) bool     { return false }
func (failingStore) IncrBy(string, int64, time.Duration) int64 { return 0 }
func (failingStore) Delete(string)                             {}

// TestResetPassword_StoreOutage_SingleUseStillFailClosed_A1 — A1 counterpart:
// even with the store failing, a single-use reset token must never be
// consumable (SetNX fails closed → ErrInvalidToken).
func TestResetPassword_StoreOutage_SingleUseStillFailClosed_A1(t *testing.T) {
	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	usedTokens := newMockUsedTokenRepo()
	audit := &mockAuditRepo{}
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	notify := &mockNotifier{}
	cfg := config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: time.Minute}
	rlCfg := config.RateLimitConfig{LoginPerAccountMax: 10000, LoginWindow: time.Minute}
	jwtCfg := config.JWTConfig{AccessTTL: time.Minute, RefreshTTL: time.Hour, ResetTTL: time.Minute, VerifyTTL: time.Hour}
	svc := NewAuthService(users, tokens, usedTokens, audit, failingStore{}, jwtMgr, cfg, rlCfg, jwtCfg, notify, nil, nil, nil, nil)

	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "gina", Email: "gina@example.com", Password: "Password1", FullName: "G",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ForgotPassword(context.Background(), "gina@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: notify.lastReset, NewPassword: "NewPassword1",
	}, "ip"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("single-use guard must fail CLOSED during a store outage, got %v", err)
	}
}

// TestConsoleNotifier_RefusesInReleaseMode_A8 — A8 regression: in
// GIN_MODE=release the console notifier must refuse to log live reset /
// verification tokens unless the operator explicitly sets
// ALLOW_TOKEN_CONSOLE=true.
func TestConsoleNotifier_RefusesInReleaseMode_A8(t *testing.T) {
	t.Setenv("GIN_MODE", "release")
	t.Setenv("ALLOW_TOKEN_CONSOLE", "")

	n := NewConsoleNotifier("no-reply@example.com")
	if err := n.SendPasswordReset(context.Background(), "a@b.com", "live-reset-token"); err == nil {
		t.Error("reset delivery must fail in release mode")
	}
	if err := n.SendEmailVerification(context.Background(), "a@b.com", "live-verify-token"); err == nil {
		t.Error("verification delivery must fail in release mode")
	}

	// Explicit operator opt-in re-enables delivery.
	t.Setenv("ALLOW_TOKEN_CONSOLE", "true")
	n = NewConsoleNotifier("no-reply@example.com")
	if err := n.SendPasswordReset(context.Background(), "a@b.com", "tok"); err != nil {
		t.Fatalf("explicit opt-in must allow delivery: %v", err)
	}

	// Debug mode is unaffected.
	t.Setenv("GIN_MODE", "debug")
	t.Setenv("ALLOW_TOKEN_CONSOLE", "")
	n = NewConsoleNotifier("no-reply@example.com")
	if err := n.SendEmailVerification(context.Background(), "a@b.com", "tok"); err != nil {
		t.Fatalf("debug mode must allow delivery: %v", err)
	}
}

// TestCredentialChange_RevokesAccessTokensViaPwdVer_A7 — A7: password
// change bumps users.pwd_version; access tokens minted afterwards carry the
// new version while pre-change tokens keep the old one (and are therefore
// rejected by AuthMiddleware, covered in the middleware tests).
func TestCredentialChange_RevokesAccessTokensViaPwdVer_A7(t *testing.T) {
	svc, users, _, _, notify, _ := buildAuthService(t,
		config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: time.Minute},
		config.RateLimitConfig{}, nil)
	if _, err := svc.Register(context.Background(), RegisterInput{
		Username: "heidi", Email: "heidi@example.com", Password: "Password1", FullName: "H",
	}); err != nil {
		t.Fatal(err)
	}
	u, _ := users.FindByEmail(context.Background(), "heidi@example.com")
	mgr := jwt.NewJWTManager("test-secret", "test-issuer")

	// Pre-change token carries pwdver=0; the live version starts at 0.
	pair, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "heidi@example.com", Password: "Password1",
	}, "ip", "ua")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := mgr.Verify(pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.PwdVer != 0 {
		t.Fatalf("pre-change token pwdver = %d, want 0", claims.PwdVer)
	}

	// Change the password: the version bumps to 1.
	if err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: u.ID, OldPassword: "Password1", NewPassword: "NewPassword1",
	}, "ip"); err != nil {
		t.Fatal(err)
	}
	live, err := svc.CurrentPwdVersion(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("pwd_version after change = %d, want 1", live)
	}

	// A fresh login carries the new version.
	pair2, _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "heidi@example.com", Password: "NewPassword1",
	}, "ip", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if claims2, err := mgr.Verify(pair2.AccessToken); err != nil || claims2.PwdVer != 1 {
		t.Fatalf("post-change token pwdver = %d err=%v, want 1", claims2.PwdVer, err)
	}

	// Password reset bumps again.
	if err := svc.ForgotPassword(context.Background(), "heidi@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: notify.lastReset, NewPassword: "ResetPassword1",
	}, "ip"); err != nil {
		t.Fatal(err)
	}
	live, err = svc.CurrentPwdVersion(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if live != 2 {
		t.Fatalf("pwd_version after reset = %d, want 2", live)
	}
}

func TestPassword_ZXCVBNScoringAndDictionaryCheck_P17(t *testing.T) {
	// 1. Rejection of username in password
	svc, _, _, _, _ := newTestAuthService()
	_, err := svc.Register(context.Background(), RegisterInput{
		Username: "superman", Email: "super@example.com", Password: "SupermanPass123", FullName: "Clark",
	})
	if !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak when password contains username, got %v", err)
	}

	// 2. Rejection of email local-part in password
	_, err = svc.Register(context.Background(), RegisterInput{
		Username: "clark", Email: "batman_fan@example.com", Password: "batman_fan_123", FullName: "Clark",
	})
	if !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak when password contains email local-part, got %v", err)
	}

	// 3. zxcvbn scoring >= 3 enforcement
	zxcvbnSvc, _, _, _, _ := newTestAuthService(WithMinPasswordScore(3))
	// Weak password (score < 3)
	_, err = zxcvbnSvc.Register(context.Background(), RegisterInput{
		Username: "alice_strong", Email: "alice_strong@example.com", Password: "Password123!", FullName: "Alice",
	})
	if !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak for zxcvbn score < 3, got %v", err)
	}

	// Strong password (score >= 3)
	_, err = zxcvbnSvc.Register(context.Background(), RegisterInput{
		Username: "alice_strong", Email: "alice_strong@example.com", Password: "correct horse battery staple 99!", FullName: "Alice",
	})
	if err != nil {
		t.Fatalf("expected high-entropy passphrase to pass zxcvbn score check, got %v", err)
	}
}

func TestGetUserAuditLog_P14(t *testing.T) {
	svc, _, _, audit, _ := newTestAuthService()
	uid := uint(42)
	audit.Record(context.Background(), &models.AuditLog{
		UserID:    &uid,
		Event:     models.AuditEventLogin,
		IPAddress: "127.0.0.1",
		Success:   true,
	})
	audit.Record(context.Background(), &models.AuditLog{
		UserID:    &uid,
		Event:     models.AuditEventPasswordChanged,
		IPAddress: "127.0.0.1",
		Success:   true,
	})

	items, total, err := svc.GetUserAuditLog(context.Background(), uid, 1, 20)
	if err != nil {
		t.Fatalf("GetUserAuditLog failed: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("want 2 items and total 2, got total=%d items=%d", total, len(items))
	}
	if items[0].Event != models.AuditEventLogin {
		t.Fatalf("unexpected event: %s", items[0].Event)
	}
}

func TestChangeEmail_Ceremony_P12(t *testing.T) {
	svc, users, _, audit, notify := newTestAuthService()
	hashed, _ := hash.HashPassword("Password123")
	u := &models.User{
		ID:              10,
		Email:           "old@example.com",
		Username:        "testuser",
		Password:        hashed,
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = users.Create(context.Background(), u)

	// 1. Wrong password fails
	err := svc.RequestChangeEmail(context.Background(), u.ID, ChangeEmailRequestInput{
		Password: "WrongPassword",
		NewEmail: "new@example.com",
	}, "127.0.0.1")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// 2. Disposable email fails
	err = svc.RequestChangeEmail(context.Background(), u.ID, ChangeEmailRequestInput{
		Password: "Password123",
		NewEmail: "test@mailinator.com",
	}, "127.0.0.1")
	if !errors.Is(err, ErrDisposableEmail) {
		t.Fatalf("expected ErrDisposableEmail, got %v", err)
	}

	// 3. Valid request stages token and sends emails
	err = svc.RequestChangeEmail(context.Background(), u.ID, ChangeEmailRequestInput{
		Password: "Password123",
		NewEmail: "new@example.com",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("RequestChangeEmail failed: %v", err)
	}
	if notify.lastVerify == "" {
		t.Fatal("expected staged verification token sent to new email")
	}

	// 4. Confirm with invalid token fails
	err = svc.ConfirmChangeEmail(context.Background(), "invalid-token", "127.0.0.1")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}

	// 5. Confirm with valid token succeeds and updates email
	err = svc.ConfirmChangeEmail(context.Background(), notify.lastVerify, "127.0.0.1")
	if err != nil {
		t.Fatalf("ConfirmChangeEmail failed: %v", err)
	}
	updated, _ := users.FindByID(context.Background(), u.ID)
	if updated.Email != "new@example.com" {
		t.Fatalf("email not updated: got %s, want new@example.com", updated.Email)
	}
	if audit.count() == 0 {
		t.Fatal("expected audit logs for change email")
	}
}

func TestDeactivateAndErase_P13(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService()
	hashed, _ := hash.HashPassword("Password123")
	u := &models.User{
		Email:           "victim@example.com",
		Username:        "victimuser",
		Password:        hashed,
		FullName:        "Victim User",
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = users.Create(context.Background(), u)

	// 1. Deactivate with bad password fails
	err := svc.DeactivateAccount(context.Background(), u.ID, "", "WrongPassword", "jti-1", "127.0.0.1")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// 2. Deactivate with correct password succeeds
	err = svc.DeactivateAccount(context.Background(), u.ID, "", "Password123", "jti-1", "127.0.0.1")
	if err != nil {
		t.Fatalf("DeactivateAccount failed: %v", err)
	}
	deactivated, _ := users.FindByID(context.Background(), u.ID)
	if deactivated.IsActive {
		t.Fatal("expected user to be inactive")
	}

	// Reactivate for erase test
	deactivated.IsActive = true
	_ = users.Update(context.Background(), deactivated)

	// 3. Erase account anonymizes PII and scrambles password
	err = svc.EraseAccount(context.Background(), u.ID, "", "Password123", "jti-2", "127.0.0.1")
	if err != nil {
		t.Fatalf("EraseAccount failed: %v", err)
	}
	erased, _ := users.FindByID(context.Background(), u.ID)
	if erased.Password != "" || erased.FullName != "" || erased.IsActive {
		t.Fatalf("account not properly erased: %+v", erased)
	}
	if !strings.HasPrefix(erased.Email, "deleted_") {
		t.Fatalf("expected anonymized email, got %s", erased.Email)
	}
}
