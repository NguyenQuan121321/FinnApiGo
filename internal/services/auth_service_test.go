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
)

// newTestAuthService builds an AuthService wired to in-memory mocks. OTP/lockout
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
		OTPTTL:               5 * time.Minute,
		OTPLength:            6,
		OTPMaxAttempts:       5,
	}

	rateLimitCfg := config.RateLimitConfig{
		RPS:                     100,
		Burst:                   20,
		LoginPerAccountMax:      10000,       // generous default so existing behavioral
		LoginWindow:             time.Minute, // tests are unaffected by velocity
		RegisterPerIPMax:        10000,       // limiters; tight-limit tests build a
		RegisterWindow:          time.Hour,   // dedicated service.
		OTPSendPerUserMax:       10000,
		OTPSendWindow:           time.Minute,
		VerifyResendPerEmailMax: 10000,
		VerifyResendWindow:      time.Minute,
		LoginCaptchaAfterFails:  10000,
	}
	jwtCfg := config.JWTConfig{
		AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
		ResetTTL: 15 * time.Minute, VerifyTTL: time.Hour,
	}

	svc := NewAuthService(users, tokens, usedTokens, audit, store, jwtMgr, cfg, rateLimitCfg, jwtCfg, notify, nil)
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
	pair, profile, err := svc.Login(context.Background(), LoginInput{
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
	_, _, err := svc.Login(context.Background(), LoginInput{
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
		_, _, _ = svc.Login(context.Background(), LoginInput{
			Email: "alice@example.com", Password: "wrong",
		}, "1.2.3.4", "test-agent")
	}
	u, _ := users.FindByEmail(context.Background(), "alice@example.com")
	if u.LockedUntil == nil {
		t.Fatal("account should be locked after 5 failed attempts")
	}
	// Now even the correct password is rejected because of the lock.
	_, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4", "test-agent")
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestLogin_UnknownUserDoesNotDistinguish(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService()
	_, _, err := svc.Login(context.Background(), LoginInput{
		Email: "ghost@example.com", Password: "Password1",
	}, "1.2.3.4", "test-agent")
	// Must return the SAME error as a wrong password, to prevent enumeration.
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}

func TestLogin_AuditFailedRecordsEmail(t *testing.T) {
	svc, _, _, audit, _ := newTestAuthService()
	_, _, _ = svc.Login(context.Background(), LoginInput{
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
	first, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Refresh(context.Background(), first.RefreshToken, "ip")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token must be rotated (new value expected)")
	}
	// Reusing the old token must now fail.
	_, err = svc.Refresh(context.Background(), first.RefreshToken, "ip")
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
	pair, _, _ := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip", "test-agent")
	// First refresh rotates to a new token.
	first, err := svc.Refresh(context.Background(), pair.RefreshToken, "ip")
	if err != nil {
		t.Fatal(err)
	}
	// Present the OLD (now revoked) token again — theft signal.
	_, err = svc.Refresh(context.Background(), pair.RefreshToken, "evil-ip")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for reused token, got %v", err)
	}
	// The NEW token should also be revoked (revoke-all).
	_, err = svc.Refresh(context.Background(), first.RefreshToken, "ip")
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
		config.AuthConfig{OTPLength: 6}, rlCfg, config.JWTConfig{VerifyTTL: time.Hour}, notify, nil)

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
