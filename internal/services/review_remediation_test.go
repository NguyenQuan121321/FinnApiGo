package services

// Regression tests for the 2026-08-31 deep-review remediation batch. Each
// test pins a bug that automated tooling could NOT catch: the passkey
// account-state bypass, the Redis-parity death of the adaptive CAPTCHA gate,
// the transactional credential change, and the new security features
// (breached-password screening, new-IP transparency alert).

import (
	"context"
	"crypto/sha1" //nolint:gosec // HIBP protocol digest (test fixture)
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
)

// --- fixtures -------------------------------------------------------------

type reviewEnv struct {
	users   *mockUserRepo
	tokens  *mockTokenRepo
	used    *mockUsedTokenRepo
	audits  *mockAuditRepo
	store   *mockStore
	notify  *mockNotifier
	authSvc *AuthService
	jwtMgr  *jwt.JWTManager
}

func newReviewEnv(opts ...AuthServiceOption) *reviewEnv {
	e := &reviewEnv{
		users:  newMockUserRepo(),
		tokens: newMockTokenRepo(),
		used:   newMockUsedTokenRepo(),
		audits: &mockAuditRepo{},
		store:  newMockStore(),
		notify: &mockNotifier{},
	}
	e.jwtMgr = jwt.NewJWTManager("review-secret", "review-issuer")
	e.authSvc = NewAuthService(
		e.users, e.tokens, e.used, e.audits, e.store, e.jwtMgr,
		config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: 15 * time.Minute, NotifyNewIPLogin: true},
		config.RateLimitConfig{RPS: 100, Burst: 20, LoginPerAccountMax: 10000, LoginCaptchaAfterFails: 5},
		config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour},
		e.notify, nil, nil, nil, nil,
		opts...,
	)
	return e
}

// waitFor polls until cond is true (the new-IP alert is sent from a
// fire-and-forget goroutine — tests must not assert on its scheduling).
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- H1: passkey issuance must enforce the account-state gate --------------

// TestPasskeyIssuanceDisabledAccountRejected pins the H1 fix: a disabled
// account must never receive tokens through the WebAuthn issuance path — the
// same gate password login, OAuth, and refresh already enforce.
func TestPasskeyIssuanceDisabledAccountRejected(t *testing.T) {
	ctx := context.Background()
	e := newReviewEnv()
	disabled := &models.User{
		Username: "h1user", Email: "h1@example.com", Password: "hash",
		Role: models.RoleUser, IsActive: false, IsEmailVerified: true,
	}
	if err := e.users.Create(ctx, disabled); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.authSvc.IssuePasskeyTokenPair(ctx, disabled, "1.2.3.4", "UA"); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("IssuePasskeyTokenPair for a disabled account: err=%v, want ErrAccountDisabled", err)
	}
	// The enabled twin still succeeds (the gate must not over-block).
	enabled := &models.User{
		Username: "h1ok", Email: "h1ok@example.com", Password: "hash",
		Role: models.RoleUser, IsActive: true, IsEmailVerified: true,
	}
	if err := e.users.Create(ctx, enabled); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.authSvc.IssuePasskeyTokenPair(ctx, enabled, "1.2.3.4", "UA"); err != nil {
		t.Fatalf("IssuePasskeyTokenPair for an active account: %v", err)
	}
}

// --- H2: the adaptive CAPTCHA gate must read Redis-shaped counters ---------

// TestLoginAdaptiveCaptchaReadsRedisCounters pins the H2 fix: Redis hands
// counters back as STRINGS; a bare int64 type assertion used to read every
// Redis counter as 0, silently disabling the gate in multi-instance mode.
// With 5 string-encoded failures on record (exactly what RedisStore.IncrBy
// produces and Get returns), the next login WITHOUT a valid captcha token
// must be rejected.
func TestLoginAdaptiveCaptchaReadsRedisCounters(t *testing.T) {
	e := newReviewEnv()
	ctx := context.Background()
	if err := e.users.Create(ctx, &models.User{
		Username: "h2user", Email: "h2@example.com", Password: mustHash("Password1"),
		Role: models.RoleUser, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate the RedisStore counter shape: the counter round-trips through
	// Redis as a string (storeCounterValue must parse it).
	e.store.Set(ipCounterKey("loginfail:", "9.9.9.9"), "5", time.Hour)

	// The gate FIRES: with >= 5 recorded failures, the CAPTCHA verifier is
	// consulted before credentials are evaluated. (A recording NoOp proves
	// invocation without changing the verdict path.)
	rec := &recordingCaptcha{}
	e.authSvc.captcha = rec
	if _, _, _, err := e.authSvc.Login(ctx, LoginInput{Email: "h2@example.com", Password: "wrong"}, "9.9.9.9", "UA"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected credential failure after gate pass: err=%v", err)
	}
	if rec.called() < 1 {
		t.Fatal("adaptive CAPTCHA gate did not fire on a string-encoded counter — the H2 bug is back")
	}

	// Control: below the threshold the gate must NOT consult the verifier.
	e2 := newReviewEnv()
	rec2 := &recordingCaptcha{}
	e2.authSvc.captcha = rec2
	_ = e2.users.Create(ctx, &models.User{
		Username: "h2b", Email: "h2b@example.com", Password: mustHash("Password1"),
		Role: models.RoleUser, IsActive: true,
	})
	e2.store.Set(ipCounterKey("loginfail:", "9.9.9.8"), "4", time.Hour)
	if _, _, _, err := e2.authSvc.Login(ctx, LoginInput{Email: "h2b@example.com", Password: "wrong"}, "9.9.9.8", "UA"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("below threshold must fall through to credential check: err=%v", err)
	}
	if rec2.called() != 0 {
		t.Fatalf("verifier consulted below threshold (%d calls)", rec2.called())
	}
}

// recordingCaptcha counts Verify invocations — the gate-fires observable.
type recordingCaptcha struct {
	mu    sync.Mutex
	calls int
}

func (c *recordingCaptcha) Verify(ctx context.Context, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return nil
}

func (c *recordingCaptcha) called() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// --- P0-d: the credential change must be atomic ----------------------------

// TestApplyCredentialChangeTransactional pins the transactional path: repos
// carrying TransactionalCredentialChanger + TxScopedTokenRevoker apply the
// whole sequence (password + lockout reset + pwd_version bump + refresh
// revocation) as one unit.
func TestApplyCredentialChangeTransactional(t *testing.T) {
	e := newReviewEnv()
	// Swap in capability-bearing repos wrapping the same mocks.
	e.authSvc.users = &txUserRepo{UserRepo: e.users}
	e.authSvc.tokens = &txTokenRepo{RefreshTokenRepo: e.tokens}
	ctx := context.Background()
	user := &models.User{
		Username: "txn", Email: "txn@example.com", Password: mustHash("OldPass1"),
		Role: models.RoleUser, IsActive: true,
	}
	if err := e.users.Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := e.applyCredentialChangeAndCheck(t, ctx, user); err != nil {
		t.Fatal(err)
	}
}

// TestApplyCredentialChangeSequentialFallback covers the mock-only fallback
// so behavior stays identical when the capability interfaces are absent.
func TestApplyCredentialChangeSequentialFallback(t *testing.T) {
	e := newReviewEnv()
	ctx := context.Background()
	user := &models.User{
		Username: "seq", Email: "seq@example.com", Password: mustHash("OldPass1"),
		Role: models.RoleUser, IsActive: true,
	}
	if err := e.users.Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := e.applyCredentialChangeAndCheck(t, ctx, user); err != nil {
		t.Fatal(err)
	}
}

func (e *reviewEnv) applyCredentialChangeAndCheck(t *testing.T, ctx context.Context, user *models.User) error {
	t.Helper()
	newHash := mustHash("NewPass9")
	if err := e.authSvc.applyCredentialChange(ctx, user, newHash); err != nil {
		return err
	}
	got, err := e.users.FindByID(ctx, user.ID)
	if err != nil || got == nil {
		return err
	}
	if got.Password != newHash {
		t.Errorf("password not updated")
	}
	if got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("lockout state not reset: %+v", got)
	}
	if got.PwdVersion != 1 {
		t.Errorf("pwd_version=%d, want 1", got.PwdVersion)
	}
	for _, rt := range e.tokens.rows {
		if !rt.Revoked {
			t.Errorf("refresh token %d not revoked by the credential change", rt.ID)
		}
	}
	return nil
}

// txUserRepo / txTokenRepo wrap the mocks with the production transactional
// capabilities so the atomic path is exercised (mock repos alone predate it).
type txUserRepo struct{ UserRepo }

func (u *txUserRepo) CredentialChangeTx(ctx context.Context, userID uint, hashedPassword string, revokeRefresh func(tx *gorm.DB) error) error {
	// Emulate the repo transaction: all user writes, then the revocation hook.
	user, err := u.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	user.Password = hashedPassword
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	user.PwdVersion++
	if err := u.Update(ctx, user); err != nil {
		return err
	}
	return revokeRefresh(nil)
}

type txTokenRepo struct{ RefreshTokenRepo }

func (r *txTokenRepo) RevokeAllForUserTx(_ *gorm.DB, userID uint) error {
	return r.RevokeAllForUser(context.Background(), userID)
}

// --- P1-g: breached-password screening --------------------------------------

func TestBreachedPasswordChecker(t *testing.T) {
	// Fake range API: respond with a REAL k-anonymity entry — the 35-char
	// suffix of whichever password the test probes, carrying count 42.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suffix := sha1SuffixOf("password")
		_, _ = w.Write([]byte("0018E4CDBB4B4C2B1F8FEF1F0E9D1EE6B06A2C41:1\n" + suffix + ":42\n"))
	}))
	defer srv.Close()

	chk := NewBreachedPasswordChecker(srv.URL+"/range/", 2*time.Second)
	if !chk.Breached(context.Background(), "password") {
		t.Fatal("known-breached password was not flagged")
	}
	if chk.Breached(context.Background(), "gibberish-not-in-corpus-9f3") {
		t.Fatal("random password flagged as breached")
	}

	// Fail-open: a dead upstream must never block a password.
	dead := NewBreachedPasswordChecker("http://127.0.0.1:1/range/", 500*time.Millisecond)
	if dead.Breached(context.Background(), "password") {
		t.Fatal("checker must fail OPEN on an unreachable upstream")
	}
}

// sha1SuffixOf returns the HIBP range-entry suffix (SHA-1 hex, minus the
// 5-char prefix the client sends).
func sha1SuffixOf(pw string) string {
	sum := sha1.Sum([]byte(pw)) //nolint:gosec // HIBP protocol digest (test fixture)
	return strings.ToUpper(hex.EncodeToString(sum[:]))[5:]
}

// TestRegisterRejectsBreachedPassword wires the checker into the service:
// a hit on the (fake) HIBP range API must surface ErrPasswordBreached.
func TestRegisterRejectsBreachedPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suffix := sha1SuffixOf("Compromised1")
		_, _ = w.Write([]byte(suffix + ":99\n")) // whatever the SHA-1 prefix is, it "hits"
	}))
	defer srv.Close()
	e := newReviewEnv(WithBreachedPasswordChecker(NewBreachedPasswordChecker(srv.URL+"/range/", time.Second)))

	_, err := e.authSvc.Register(context.Background(), RegisterInput{
		Username: "pwnd", Email: "pwnd@example.com", Password: "Compromised1", FullName: "P",
	})
	if !errors.Is(err, ErrPasswordBreached) {
		t.Fatalf("err=%v, want ErrPasswordBreached", err)
	}
	if len(e.users.users) != 0 {
		t.Fatal("no user row may be created for a breached password")
	}
}

// --- P1-h: new-IP transparency alert ----------------------------------------

// TestNewIPLoginNotificationOnFirstLogin pins the transparency feature: the
// first login from an IP sends exactly one alert; a repeat login from the
// same IP sends none. (No risk-based step-up — the flow itself is unchanged.)
func TestNewIPLoginNotificationOnFirstLogin(t *testing.T) {
	e := newReviewEnv()
	ctx := context.Background()
	if err := e.users.Create(ctx, &models.User{
		Username: "alert", Email: "alert@example.com", Password: mustHash("Password1"),
		Role: models.RoleUser, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.authSvc.Login(ctx, LoginInput{Email: "alert@example.com", Password: "Password1"}, "77.1.2.3", "Firefox/120"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.notify.alertsSent == 1 })
	if e.notify.alertsSent != 1 {
		t.Fatalf("alertsSent=%d, want 1 on first login from a new IP", e.notify.alertsSent)
	}
	if e.notify.lastAlertIP != "77.1.2.3" {
		t.Fatalf("alert IP=%q", e.notify.lastAlertIP)
	}
	// Same IP again → no second alert (lookback key already set).
	if _, _, _, err := e.authSvc.Login(ctx, LoginInput{Email: "alert@example.com", Password: "Password1"}, "77.1.2.3", "Firefox/120"); err != nil {
		t.Fatal(err)
	}
	if e.notify.alertsSent != 1 {
		t.Fatalf("alertsSent=%d, want 1 — repeat IP must not re-alert", e.notify.alertsSent)
	}
	// A different IP → one more alert.
	if _, _, _, err := e.authSvc.Login(ctx, LoginInput{Email: "alert@example.com", Password: "Password1"}, "78.4.5.6", "Firefox/120"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.notify.alertsSent == 2 })
	if e.notify.alertsSent != 2 {
		t.Fatalf("alertsSent=%d, want 2 for a genuinely new IP", e.notify.alertsSent)
	}
}

// TestNewIPNotificationDisabledByConfig covers the operator opt-out.
func TestNewIPNotificationDisabledByConfig(t *testing.T) {
	e := newReviewEnv()
	e.authSvc.cfg.NotifyNewIPLogin = false
	ctx := context.Background()
	if err := e.users.Create(ctx, &models.User{
		Username: "quiet", Email: "quiet@example.com", Password: mustHash("Password1"),
		Role: models.RoleUser, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.authSvc.Login(ctx, LoginInput{Email: "quiet@example.com", Password: "Password1"}, "5.5.5.5", "UA"); err != nil {
		t.Fatal(err)
	}
	if e.notify.alertsSent != 0 {
		t.Fatalf("alertsSent=%d, want 0 when LOGIN_NOTIFY_NEW_IP=false", e.notify.alertsSent)
	}
}

// --- store parity: Take ------------------------------------------------------

// TestMockStoreTakeAtomicity — Take deletes exactly once; a second Take must
// miss (the single-use consumption contract the OAuth state and WebAuthn
// challenges depend on).
func TestMockStoreTakeAtomicity(t *testing.T) {
	ms := newMockStore()
	ms.SetNX("k", "v", time.Minute)
	if v, ok := ms.Take("k"); !ok || v != "v" {
		t.Fatalf("first Take=%v,%v", v, ok)
	}
	if _, ok := ms.Take("k"); ok {
		t.Fatal("second Take must miss — Take is single-use")
	}
}

// TestIPCounterKeyCollapsesIPv6 pins the cardinality defense: addresses in
// the same /64 collapse to one key; IPv4 is kept verbatim.
func TestIPCounterKeyCollapsesIPv6(t *testing.T) {
	a := ipCounterKey("loginfail:", "2001:db8:1:2:aaaa:bbbb:cccc:1")
	b := ipCounterKey("loginfail:", "2001:db8:1:2:1111:2222:3333:4444")
	if a != b {
		t.Fatalf("same /64 must collapse to one key: %q vs %q", a, b)
	}
	if v4 := ipCounterKey("loginfail:", "9.9.9.9"); v4 != "loginfail:9.9.9.9" {
		t.Fatalf("IPv4 key must be verbatim: %q", v4)
	}
}
