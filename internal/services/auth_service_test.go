package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
)

// newTestAuthService builds an AuthService wired to in-memory mocks. Lockout
// knobs are tuned short for test speed.
func newTestAuthService() (*AuthService, *mockUserRepo, *mockTokenRepo, *mockAuditRepo, *mockNotifier) {
	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	usedTokens := newMockUsedTokenRepo()
	store := newMockStore()
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

	svc := NewAuthService(users, tokens, usedTokens, audit, store, jwtMgr, cfg, rateLimitCfg, jwtCfg, notify, nil, nil, nil, nil)
	return svc, users, tokens, audit, notify
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
	}
	if u.Password == "Password1" {
		t.Error("password must be hashed, not stored in plaintext")
	}
	if !hash.CheckPassword(u.Password, "Password1") {
		t.Error("hashed password does not verify")
	}
}

func TestRegister_RejectsDuplicateEmail(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	in := RegisterInput{Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "A"}
	if _, err := svc.Register(context.Background(), in); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	_, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice2", Email: "alice@example.com", Password: "Password1", FullName: "A",
	})
	if !errors.Is(err, ErrEmailExists) {
		t.Errorf("expected ErrEmailExists, got %v", err)
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
	sessions, err := svc.ListSessions(context.Background(), 1)
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

	sessions, err := svc.ListSessions(context.Background(), 1)
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
	if err := svc.RevokeSession(context.Background(), 1, 1, "10.0.0.1"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	// Verify it no longer appears in the active list.
	sessions, _ := svc.ListSessions(context.Background(), 1)
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
	err := svc.RevokeSession(context.Background(), 9999, 1, "ip")
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
	err := svc.RevokeSession(context.Background(), 1, 2, "evil")
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
	sessions, err := svc.ListSessions(context.Background(), 1)
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
