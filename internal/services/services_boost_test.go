package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-webauthn/webauthn/protocol"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/geo"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
	"golang.org/x/oauth2"
)

func TestCaptchaVerifiers(t *testing.T) {
	ctx := context.Background()

	// 1. NoOpCaptchaVerifier
	noop := NoOpCaptchaVerifier{}
	if err := noop.Verify(ctx, "any"); err != nil {
		t.Fatalf("NoOpCaptchaVerifier failed: %v", err)
	}

	// 2. TurnstileVerifier empty token
	v := NewTurnstileVerifier("test-secret")
	if err := v.Verify(ctx, "   "); !errors.Is(err, ErrCaptchaRejected) {
		t.Fatalf("empty token should return ErrCaptchaRejected, got %v", err)
	}

	// 3. Mock server - success
	srvSuccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success": true}`))
	}))
	defer srvSuccess.Close()

	v.WithEndpoint(srvSuccess.URL)
	if err := v.Verify(ctx, "valid-token"); err != nil {
		t.Fatalf("TurnstileVerifier success case failed: %v", err)
	}

	// 4. Mock server - failure
	srvFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success": false, "error-codes": ["invalid-input-response"]}`))
	}))
	defer srvFail.Close()

	v.WithEndpoint(srvFail.URL)
	if err := v.Verify(ctx, "bad-token"); !errors.Is(err, ErrCaptchaRejected) {
		t.Fatalf("TurnstileVerifier fail case should return ErrCaptchaRejected, got %v", err)
	}

	// 5. Mock server - decode error
	srvBadJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srvBadJSON.Close()

	v.WithEndpoint(srvBadJSON.URL)
	if err := v.Verify(ctx, "tok"); err == nil {
		t.Fatal("expected decode error, got nil")
	}

	// 6. Cancelled context
	cancCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := v.Verify(cancCtx, "tok"); err == nil {
		t.Fatal("expected context error, got nil")
	}
}

func TestGoogleVerifier_AndClaims(t *testing.T) {
	claims := map[string]interface{}{
		"email":          "user@example.com",
		"email_verified": true,
		"bool_str":       "true",
		"name":           "Alice",
		"picture":        "https://example.com/p.jpg",
		"nonce":          "nonce-123",
		"num":            123,
	}

	if s := claimString(claims, "email"); s != "user@example.com" {
		t.Fatalf("claimString email mismatch: %s", s)
	}
	if s := claimString(claims, "missing"); s != "" {
		t.Fatalf("claimString missing should be empty: %s", s)
	}
	if s := claimString(claims, "num"); s != "" {
		t.Fatalf("claimString num should be empty: %s", s)
	}

	if b := claimBool(claims, "email_verified"); !b {
		t.Fatal("claimBool bool expected true")
	}
	if b := claimBool(claims, "bool_str"); !b {
		t.Fatal("claimBool bool_str expected true")
	}
	if b := claimBool(claims, "missing"); b {
		t.Fatal("claimBool missing expected false")
	}
	if b := claimBool(claims, "num"); b {
		t.Fatal("claimBool num expected false")
	}

	v := NewProductionGoogleVerifier("client-id-123")
	if v.clientID != "client-id-123" {
		t.Fatalf("clientID mismatch: %s", v.clientID)
	}
	_, err := v.Verify(context.Background(), "invalid-raw-token")
	if !errors.Is(err, ErrOAuthTokenVerificationFailed) {
		t.Fatalf("expected ErrOAuthTokenVerificationFailed, got %v", err)
	}
}

func TestConsoleNotifier_AllAlerts(t *testing.T) {
	ctx := context.Background()
	n := NewConsoleNotifier("noreply@example.com")

	if err := n.SendNewLoginAlert(ctx, "u@ex.com", "1.2.3.4", "Firefox"); err != nil {
		t.Fatal(err)
	}
	if err := n.SendDuplicateRegisterAlert(ctx, "u@ex.com"); err != nil {
		t.Fatal(err)
	}
	if err := n.SendSecurityAlert(ctx, "u@ex.com", "Alert", "detail"); err != nil {
		t.Fatal(err)
	}
	if err := n.SendPasswordReset(ctx, "u@ex.com", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := n.SendEmailVerification(ctx, "u@ex.com", "tok"); err != nil {
		t.Fatal(err)
	}

	// Release mode without ALLOW_TOKEN_CONSOLE
	t.Setenv("GIN_MODE", "release")
	t.Setenv("ALLOW_TOKEN_CONSOLE", "")
	nRelease := NewConsoleNotifier("noreply@example.com")
	if err := nRelease.SendPasswordReset(ctx, "u@ex.com", "tok"); !errors.Is(err, errConsoleTokensSuppressed) {
		t.Fatalf("expected errConsoleTokensSuppressed, got %v", err)
	}
	if err := nRelease.SendEmailVerification(ctx, "u@ex.com", "tok"); !errors.Is(err, errConsoleTokensSuppressed) {
		t.Fatalf("expected errConsoleTokensSuppressed, got %v", err)
	}
}

func TestOAuthService_Helpers(t *testing.T) {
	ctx := context.Background()

	// 1. generateUsernameFromEmail
	if u := generateUsernameFromEmail("test@example.com"); u != "test" {
		t.Fatalf("expected test, got %s", u)
	}
	if u := generateUsernameFromEmail("noatsign"); u != "noatsign" {
		t.Fatalf("expected noatsign, got %s", u)
	}

	// 2. randomSuffix
	suf, err := randomSuffix()
	if err != nil || len(suf) != 6 {
		t.Fatalf("randomSuffix failed: suf=%s err=%v", suf, err)
	}

	// 3. NewGoogleOAuthClient
	if client := NewGoogleOAuthClient("", "secret", "https://redirect"); client != nil {
		t.Fatal("expected nil client for empty clientID")
	}
	if client := NewGoogleOAuthClient("client", "secret", ""); client != nil {
		t.Fatal("expected nil client for empty redirectURL")
	}

	client := NewGoogleOAuthClient("client", "secret", "https://example.com/callback")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	urlWithNonce := client.AuthCodeURL("state1", "chal1", "nonce1")
	if !strings.Contains(urlWithNonce, "nonce=nonce1") {
		t.Fatalf("expected nonce in URL: %s", urlWithNonce)
	}
	urlNoNonce := client.AuthCodeURL("state1", "chal1", "")
	if strings.Contains(urlNoNonce, "nonce=") {
		t.Fatalf("unexpected nonce in URL: %s", urlNoNonce)
	}

	_, err = client.Exchange(ctx, "bad-code", "bad-verifier")
	if err == nil {
		t.Fatal("expected exchange error with bad code")
	}
}

func TestBreachedPassword_AllBranches(t *testing.T) {
	ctx := context.Background()

	// Default constructor
	checker := NewBreachedPasswordChecker("", 0)
	if checker.endpoint != DefaultHIBPEndpoint {
		t.Fatalf("default endpoint mismatch: %s", checker.endpoint)
	}

	// Edge checks
	if checker.Breached(ctx, "") {
		t.Fatal("empty password must not be breached")
	}
	var nilChecker *BreachedPasswordChecker
	if nilChecker.Breached(ctx, "any") {
		t.Fatal("nil checker must fail open (return false)")
	}

	pwd := "SuperSecret123!"
	prefix, suffix := calculateHIBPSHA1Prefix(pwd)

	// Mock server returning match
	srvMatch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, prefix) {
			_, _ = fmt.Fprintf(w, "%s:42\r\nOTHER:1\r\n", suffix)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srvMatch.Close()

	cMatch := NewBreachedPasswordChecker(srvMatch.URL+"/", time.Second)
	if !cMatch.Breached(ctx, pwd) {
		t.Fatal("expected password to be flagged as breached")
	}

	// Mock server returning no match
	srvNoMatch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "OTHERHASH12345:1\r\n")
	}))
	defer srvNoMatch.Close()

	cNoMatch := NewBreachedPasswordChecker(srvNoMatch.URL+"/", time.Second)
	if cNoMatch.Breached(ctx, pwd) {
		t.Fatal("expected password to not be flagged as breached")
	}

	// Mock server returning 500 (fail open)
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()

	c500 := NewBreachedPasswordChecker(srv500.URL+"/", time.Second)
	if c500.Breached(ctx, pwd) {
		t.Fatal("expected fail open (false) on 500 error")
	}
}

func TestSMTPNotifier_Helpers(t *testing.T) {
	ctx := context.Background()

	// validEnvelopeAddr
	if err := validEnvelopeAddr(""); err == nil {
		t.Fatal("expected error for empty addr")
	}
	if err := validEnvelopeAddr(strings.Repeat("a", 255)); err == nil {
		t.Fatal("expected error for addr > 254")
	}
	if err := validEnvelopeAddr("noat"); err == nil {
		t.Fatal("expected error for no @")
	}
	if err := validEnvelopeAddr("a@b@c"); err == nil {
		t.Fatal("expected error for multiple @")
	}
	if err := validEnvelopeAddr("has space@b.com"); err == nil {
		t.Fatal("expected error for space")
	}
	if err := validEnvelopeAddr("user@example.com"); err != nil {
		t.Fatalf("valid addr failed: %v", err)
	}

	// validHeaderValue
	if err := validHeaderValue("clean header"); err != nil {
		t.Fatalf("clean header failed: %v", err)
	}
	if err := validHeaderValue("header\r\ninjection"); err == nil {
		t.Fatal("expected error for line break in header")
	}

	// safeMailDisplayValue
	if s := safeMailDisplayValue("line1\r\nline2"); s != "line1 line2" {
		t.Fatalf("safeMailDisplayValue mismatch: %s", s)
	}

	// safeMailIP
	if ip := safeMailIP("1.2.3.4"); ip != "1.2.3.4" {
		t.Fatalf("safeMailIP valid mismatch: %s", ip)
	}
	if ip := safeMailIP("not-an-ip"); ip != "Unknown" {
		t.Fatalf("safeMailIP invalid mismatch: %s", ip)
	}

	// Enabled and send
	nDisabled := &SMTPNotifier{}
	if nDisabled.Enabled() {
		t.Fatal("expected disabled for empty host/from")
	}
	if err := nDisabled.send(ctx, "a@b.com", "sub", "body"); err == nil {
		t.Fatal("expected error from unconfigured notifier")
	}

	nEnabled := &SMTPNotifier{host: "smtp.example.com", from: "from@example.com"}
	if !nEnabled.Enabled() {
		t.Fatal("expected enabled")
	}
	if err := nEnabled.send(ctx, "invalid-to", "sub", "body"); err == nil {
		t.Fatal("expected error for invalid to")
	}
	nEnabledBadFrom := &SMTPNotifier{host: "smtp.example.com", from: "invalid-from"}
	if err := nEnabledBadFrom.send(ctx, "to@example.com", "sub", "body"); err == nil {
		t.Fatal("expected error for bad from")
	}
	if err := nEnabled.send(ctx, "to@example.com", "bad\r\nsub", "body"); err == nil {
		t.Fatal("expected error for bad subject")
	}
}

func TestWebhookService_BlockedIPAndDialContext(t *testing.T) {
	// blockedIP
	if !blockedIP(net.ParseIP("127.0.0.1")) {
		t.Error("127.0.0.1 must be blocked")
	}
	if !blockedIP(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 must be blocked")
	}
	if !blockedIP(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 must be blocked")
	}
	if !blockedIP(net.ParseIP("::1")) {
		t.Error("::1 must be blocked")
	}
	if blockedIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 must not be blocked")
	}
	// IPv4-mapped IPv6
	if !blockedIP(net.ParseIP("::ffff:127.0.0.1")) {
		t.Error("::ffff:127.0.0.1 must be blocked")
	}
	if blockedIP(net.ParseIP("::ffff:8.8.8.8")) {
		t.Error("::ffff:8.8.8.8 must not be blocked")
	}

	// DialContext
	wh := NewWebhookService(nil)
	tr := wh.httpClient.Transport.(*http.Transport)

	// allowLocalhost = true
	wh.SetAllowLocalhost(true)
	_, _ = tr.DialContext(context.Background(), "tcp", "127.0.0.1:0")

	// allowLocalhost = false
	wh.SetAllowLocalhost(false)
	// Invalid addr
	_, err := tr.DialContext(context.Background(), "tcp", "no-port")
	if err == nil {
		t.Fatal("expected error for no-port addr")
	}
	// Localhost addr blocked
	_, err = tr.DialContext(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("expected restricted error for 127.0.0.1, got %v", err)
	}
}

func TestTOTPService_StoreCounterValue(t *testing.T) {
	memStore := store.NewInMemoryStore(0)
	if v := storeCounterValue(memStore, "missing"); v != 0 {
		t.Fatalf("expected 0 for missing key, got %d", v)
	}

	memStore.Set("int64_key", int64(100), 0)
	if v := storeCounterValue(memStore, "int64_key"); v != 100 {
		t.Fatalf("expected 100 for int64, got %d", v)
	}

	memStore.Set("int_key", 50, 0)
	if v := storeCounterValue(memStore, "int_key"); v != 50 {
		t.Fatalf("expected 50 for int, got %d", v)
	}

	memStore.Set("str_key", "75", 0)
	if v := storeCounterValue(memStore, "str_key"); v != 75 {
		t.Fatalf("expected 75 for str, got %d", v)
	}

	memStore.Set("other_key", []byte("bad"), 0)
	if v := storeCounterValue(memStore, "other_key"); v != 0 {
		t.Fatalf("expected 0 for other type, got %d", v)
	}
}

func TestAsyncAuditWriter_Coverage(t *testing.T) {
	ctx := context.Background()

	// 1. Sync mode without repo
	wSync := NewAsyncAuditWriter(nil, nil, config.AuditConfig{})
	if b := wSync.Buffered(); b != 0 {
		t.Fatalf("expected 0 buffered in sync mode, got %d", b)
	}
	logs, total, err := wSync.FindByUserIDPaginated(ctx, 1, 1, 10)
	if err != nil || total != 0 || len(logs) != 0 {
		t.Fatal("expected empty paginated results without repo")
	}
	if err := wSync.AnonymizeUser(ctx, 1); err != nil {
		t.Fatal(err)
	}
	all, err := wSync.StreamAll(ctx, "default")
	if err != nil || len(all) != 0 {
		t.Fatal("expected empty stream without repo")
	}
	wSync.Close()

	// 2. Real DB repo
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.AuditLog{})
	repo := repositories.NewAuditRepository(db)

	wReal := NewAsyncAuditWriter(repo, repo, config.AuditConfig{})
	wReal.Record(ctx, &models.AuditLog{
		TenantID: "default",
		Event:    models.AuditEventLogin,
		Success:  true,
	})

	_, _, err = wReal.FindByUserIDPaginated(ctx, 1, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := wReal.AnonymizeUser(ctx, 1); err != nil {
		t.Fatal(err)
	}
	all, err = wReal.StreamAll(ctx, "default")
	if err != nil || len(all) != 1 {
		t.Fatalf("expected 1 record in StreamAll, got %d", len(all))
	}
}

func TestAuthService_Me_CurrentPwdVersion_ListSessions_RevokeSession(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
		&models.PasskeyCredential{},
		&models.OAuthIdentity{},
	)

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{MaxLoginAttempts: 5, BcryptCost: hash.MinCost}
	rlCfg := config.RateLimitConfig{}
	jwtCfg := config.JWTConfig{AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour}
	notify := NewConsoleNotifier("noreply@example.com")

	u := &models.User{
		Username:   "testuser",
		Email:      "test@example.com",
		Password:   "hashedpassword",
		Role:       models.RoleUser,
		IsActive:   true,
		PwdVersion: 1,
	}
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithSessionRepo(sessionRepo),
		WithMinPasswordScore(0),
	)

	// 1. Me
	prof, err := svc.Me(ctx, u.ID)
	if err != nil || prof.Email != u.Email {
		t.Fatalf("Me failed: %v, %v", prof, err)
	}
	_, err = svc.Me(ctx, 999999)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	// 2. CurrentPwdVersion
	// Cache miss -> DB hit
	v, err := svc.CurrentPwdVersion(ctx, u.ID)
	if err != nil || v != 1 {
		t.Fatalf("CurrentPwdVersion DB hit failed: v=%d, err=%v", v, err)
	}
	// Cache hit (int64)
	v, err = svc.CurrentPwdVersion(ctx, u.ID)
	if err != nil || v != 1 {
		t.Fatalf("CurrentPwdVersion cache hit failed: v=%d, err=%v", v, err)
	}
	// Cache hit (string)
	memStore.Set(fmt.Sprintf("pwdver:%d", u.ID), "2", time.Minute)
	v, err = svc.CurrentPwdVersion(ctx, u.ID)
	if err != nil || v != 2 {
		t.Fatalf("CurrentPwdVersion string cache hit failed: v=%d, err=%v", v, err)
	}
	// Missing user
	v, err = svc.CurrentPwdVersion(ctx, 888888)
	if err != nil || v != 0 {
		t.Fatalf("CurrentPwdVersion missing user expected 0, got %d, err=%v", v, err)
	}

	// 3. markTokenUsed
	if ok := svc.markTokenUsed("jti-1", time.Minute); !ok {
		t.Fatal("first markTokenUsed should return true")
	}
	if ok := svc.markTokenUsed("jti-1", time.Minute); ok {
		t.Fatal("second markTokenUsed should return false")
	}

	// 4. GetUserAuditLog
	items, total, err := svc.GetUserAuditLog(ctx, u.ID, 1, 10)
	if err != nil {
		t.Fatalf("GetUserAuditLog failed: %v", err)
	}
	_ = total
	_ = items

	// 5. ListSessions & RevokeSession with sessionRepo
	sess := &models.Session{
		ID:           "s-456",
		UserID:       u.ID,
		ExpiresAt:    time.Now().Add(time.Hour),
		LastActiveAt: time.Now(),
	}
	_ = sessionRepo.Create(ctx, sess)

	sessions, err := svc.ListSessions(ctx, u.ID, "s-456")
	if err != nil || len(sessions) != 1 || !sessions[0].IsCurrent {
		t.Fatalf("ListSessions failed: %v, %v", sessions, err)
	}

	if err := svc.RevokeSession(ctx, "s-456", u.ID, "1.2.3.4"); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
	if err := svc.RevokeSession(ctx, "nonexistent", u.ID, "1.2.3.4"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	// 6. Legacy ListSessions & RevokeSession without sessionRepo
	svcLegacy := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)

	// #nosec G101 -- test mock token hash, not real credentials
	rt := &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: "tok-hash",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = tokenRepo.Create(ctx, rt)

	legacyList, err := svcLegacy.ListSessions(ctx, u.ID, "")
	if err != nil || len(legacyList) != 1 {
		t.Fatalf("legacy ListSessions failed: %v, %v", legacyList, err)
	}

	if err := svcLegacy.RevokeSession(ctx, fmt.Sprintf("%d", rt.ID), u.ID, "1.2.3.4"); err != nil {
		t.Fatalf("legacy RevokeSession failed: %v", err)
	}
	if err := svcLegacy.RevokeSession(ctx, "not-a-number", u.ID, "1.2.3.4"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for non-numeric ID, got %v", err)
	}

	// 7. Logout & LogoutAll
	rawRefresh := "raw-refresh-tok"
	// #nosec G101 -- test mock token hash, not real credentials
	rtLogout := &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: "921820464fba282b82142475ab5215c26cc800f1c9fc63630f9a76d8b688d0f1", // sha256 of rawRefresh
		ExpiresAt: time.Now().Add(time.Hour),
		SessionID: "sess-to-logout",
	}
	_ = tokenRepo.Create(ctx, rtLogout)
	_ = sessionRepo.Create(ctx, &models.Session{
		ID:        "sess-to-logout",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	if err := svc.Logout(ctx, rawRefresh, "access-jti-1", "1.1.1.1"); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}
	// Idempotent Logout
	if err := svc.Logout(ctx, "unknown-tok", "", "1.1.1.1"); err != nil {
		t.Fatalf("idempotent Logout failed: %v", err)
	}

	if err := svc.LogoutAll(ctx, u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("LogoutAll failed: %v", err)
	}
}

func TestAuthService_AdvancedBranches(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.AuditLog{}, &models.UsedToken{}, &models.Session{})

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	u := &models.User{Username: "bob", Email: "bob@example.com", Password: "oldpassword", Role: models.RoleUser, IsActive: true}
	_ = userRepo.Create(ctx, u)

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		config.AuthConfig{MaxLoginAttempts: 5}, config.RateLimitConfig{}, config.JWTConfig{AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour},
		NewConsoleNotifier("noreply@example.com"), NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithSessionRepo(sessionRepo),
	)

	// 1. handleTokenReuse with session family
	sess := &models.Session{ID: "reuse-sess", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}
	_ = sessionRepo.Create(ctx, sess)
	// #nosec G101 -- test mock token hash, not real credentials
	rt1 := &models.RefreshToken{UserID: u.ID, SessionID: "reuse-sess", TokenHash: "tok-reuse-1", ExpiresAt: time.Now().Add(time.Hour)}
	_ = tokenRepo.Create(ctx, rt1)
	svc.handleTokenReuse(ctx, rt1, "1.2.3.4", "detail reuse")

	// handleTokenReuse without session family (legacy row)
	// #nosec G101 -- test mock token hash, not real credentials
	rtLegacy := &models.RefreshToken{UserID: u.ID, TokenHash: "tok-reuse-legacy", ExpiresAt: time.Now().Add(time.Hour)}
	_ = tokenRepo.Create(ctx, rtLegacy)
	svc.handleTokenReuse(ctx, rtLegacy, "1.2.3.4", "detail legacy reuse")

	// 2. notifySecurityAsync
	svc.notifySecurityAsync(ctx, u.ID, "Event", "Body")
	svc.notifySecurityAsync(ctx, 999999, "Event", "Body")
	svcNoNotify := &AuthService{users: userRepo}
	svcNoNotify.notifySecurityAsync(ctx, u.ID, "Event", "Body")

	// 3. validatePassword
	if err := validatePassword("short", 0); !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak for short, got %v", err)
	}
	if err := validatePassword(strings.Repeat("a", 100), 0); !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak for too long, got %v", err)
	}
	if err := validatePassword("onlylettersnohash", 0); !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak for no digits, got %v", err)
	}
	if err := validatePassword("1234567890", 0); !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak for no letters, got %v", err)
	}
	if err := validatePassword("GoodPassword123!", 0); err != nil {
		t.Fatalf("expected nil for valid password, got %v", err)
	}

	// 4. ipCounterKey
	k := ipCounterKey("prefix:", "1.2.3.4")
	if !strings.HasPrefix(k, "prefix:") {
		t.Fatalf("unexpected ipCounterKey: %s", k)
	}

	// 5. consumeSingleUseToken & markTokenDurable
	if !svc.consumeSingleUseToken(ctx, "fresh-jti", time.Minute) {
		t.Fatal("expected fresh-jti to be fresh")
	}
	_ = svc.markTokenDurable(ctx, "fresh-jti", "access", u.ID, time.Now().Add(time.Hour))
	if svc.consumeSingleUseToken(ctx, "fresh-jti", time.Minute) {
		t.Fatal("expected already consumed jti to return false")
	}

	// 6. applyCredentialChange
	if err := svc.applyCredentialChange(ctx, u, "newhash-pwd"); err != nil {
		t.Fatalf("applyCredentialChange failed: %v", err)
	}
}

func TestPasskey_And_TOTP_Helpers(t *testing.T) {
	// 1. transportsJSON
	if j := transportsJSON(nil); j != "[]" {
		t.Fatalf("transportsJSON nil expected [], got %s", j)
	}

	// 2. clientIPFrom
	if ip := clientIPFrom(nil); ip != "" {
		t.Fatalf("clientIPFrom nil expected empty, got %s", ip)
	}
	req := &http.Request{RemoteAddr: "192.168.1.1:8080"}
	if ip := clientIPFrom(req); ip != "192.168.1.1" {
		t.Fatalf("clientIPFrom expected 192.168.1.1, got %s", ip)
	}
	reqNoPort := &http.Request{RemoteAddr: "192.168.1.1"}
	if ip := clientIPFrom(reqNoPort); ip != "192.168.1.1" {
		t.Fatalf("clientIPFrom expected 192.168.1.1, got %s", ip)
	}

	// 3. lastIndexByte
	if idx := lastIndexByte("hello:world", ':'); idx != 5 {
		t.Fatalf("lastIndexByte expected 5, got %d", idx)
	}
	if idx := lastIndexByte("hello", ':'); idx != -1 {
		t.Fatalf("lastIndexByte expected -1, got %d", idx)
	}

	// 4. IsTOTPError
	if !IsTOTPError(ErrInvalidCode) {
		t.Fatal("expected true for ErrInvalidCode")
	}
	if !IsTOTPError(ErrRateLimited) {
		t.Fatal("expected true for ErrRateLimited")
	}
	if IsTOTPError(errors.New("other")) {
		t.Fatal("expected false for other error")
	}
}

func TestAdminService_AllMethods(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.AuditLog{}, &models.Session{})

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	memStore := store.NewInMemoryStore(0)

	admin := &models.User{Username: "admin", Email: "admin@example.com", Role: models.RoleAdmin, IsActive: true}
	user1 := &models.User{Username: "user1", Email: "user1@example.com", Role: models.RoleUser, IsActive: true}
	_ = userRepo.Create(ctx, admin)
	_ = userRepo.Create(ctx, user1)

	adminSvc := NewAdminService(userRepo, sessionRepo, tokenRepo, auditRepo, memStore)

	// 1. ListUsers
	profiles, total, err := adminSvc.ListUsers(ctx, 1, 10, "")
	if err != nil || total != 2 || len(profiles) != 2 {
		t.Fatalf("ListUsers failed: total=%d, len=%d, err=%v", total, len(profiles), err)
	}

	// 2. LockUser cannot lock self
	if err := adminSvc.LockUser(ctx, admin.ID, admin.ID, time.Hour, "1.1.1.1"); !errors.Is(err, ErrCannotLockSelf) {
		t.Fatalf("expected ErrCannotLockSelf, got %v", err)
	}
	// LockUser missing target
	if err := adminSvc.LockUser(ctx, admin.ID, 999999, time.Hour, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// LockUser success
	if err := adminSvc.LockUser(ctx, admin.ID, user1.ID, 0, "1.1.1.1"); err != nil {
		t.Fatalf("LockUser failed: %v", err)
	}

	// 3. UnlockUser missing target & success
	if err := adminSvc.UnlockUser(ctx, admin.ID, 999999, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	if err := adminSvc.UnlockUser(ctx, admin.ID, user1.ID, "1.1.1.1"); err != nil {
		t.Fatalf("UnlockUser failed: %v", err)
	}

	// 4. ForceLogout missing target & success
	if err := adminSvc.ForceLogout(ctx, admin.ID, 999999, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	if err := adminSvc.ForceLogout(ctx, admin.ID, user1.ID, "1.1.1.1"); err != nil {
		t.Fatalf("ForceLogout failed: %v", err)
	}

	// 5. ListTenantSessions
	sessions, err := adminSvc.ListTenantSessions(ctx)
	if err != nil {
		t.Fatalf("ListTenantSessions failed: %v", err)
	}
	_ = sessions

	// 6. ExportAuditLogs (CSV and NDJSON)
	auditRepo.Record(ctx, &models.AuditLog{TenantID: "default", Event: models.AuditEventLogin, Success: true})
	csvBytes, mimeCSV, err := adminSvc.ExportAuditLogs(ctx, "csv")
	if err != nil || mimeCSV != "text/csv" || len(csvBytes) == 0 {
		t.Fatalf("ExportAuditLogs CSV failed: %v, %s", err, mimeCSV)
	}
	ndjsonBytes, mimeND, err := adminSvc.ExportAuditLogs(ctx, "ndjson")
	if err != nil || mimeND != "application/x-ndjson" || len(ndjsonBytes) == 0 {
		t.Fatalf("ExportAuditLogs NDJSON failed: %v, %s", err, mimeND)
	}
}

func TestTrustedDeviceService_AllMethods(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.TrustedDevice{})
	repo := repositories.NewTrustedDeviceRepository(db)
	svc := NewTrustedDeviceService(repo)

	// Issue
	token, exp, err := svc.Issue(ctx, 1, "Chrome on Mac", "1.2.3.4")
	if err != nil || token == "" || exp.Before(time.Now()) {
		t.Fatalf("Issue failed: tok=%s, exp=%v, err=%v", token, exp, err)
	}

	// Validate (valid, then invalid)
	valid, err := svc.Validate(ctx, 1, token)
	if err != nil || !valid {
		t.Fatalf("Validate failed: valid=%v, err=%v", valid, err)
	}
	valid, err = svc.Validate(ctx, 1, "wrong-token")
	if err != nil || valid {
		t.Fatalf("Validate wrong token should be false, got %v, err=%v", valid, err)
	}

	// ListByUser
	devices, err := svc.ListByUser(ctx, 1)
	if err != nil || len(devices) != 1 {
		t.Fatalf("ListByUser failed: len=%d, err=%v", len(devices), err)
	}

	// Revoke
	if err := svc.Revoke(ctx, devices[0].ID, 1); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
}

func TestAuthService_CoreLifecycleFlows(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
		&models.TOTPDevice{},
	)

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{MaxLoginAttempts: 5, BcryptCost: hash.MinCost}
	jwtCfg := config.JWTConfig{
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		ResetTTL:      time.Hour,
		VerifyTTL:     time.Hour,
		MFAPendingTTL: 5 * time.Minute,
	}
	notify := NewConsoleNotifier("noreply@example.com")
	totpVal := &mockTOTPValidator{err: ErrInvalidCode}

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, config.RateLimitConfig{}, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		totpRepo, totpVal,
		WithSessionRepo(sessionRepo),
	)

	hashedOld, _ := hash.HashPassword("OldPassword123!", hash.MinCost)
	u := &models.User{
		Username:        "charlie",
		Email:           "charlie@example.com",
		Password:        hashedOld,
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: false,
		PwdVersion:      1,
	}
	_ = userRepo.Create(ctx, u)

	// 1. ForgotPassword
	if err := svc.ForgotPassword(ctx, "nonexistent@example.com", "1.1.1.1"); err != nil {
		t.Fatalf("ForgotPassword for missing user must return nil (silent), got %v", err)
	}
	if err := svc.ForgotPassword(ctx, u.Email, "1.1.1.1"); err != nil {
		t.Fatalf("ForgotPassword for existing user failed: %v", err)
	}

	// 2. ResetPassword
	resetTok, _ := jwtMgr.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeReset, time.Hour)
	// Invalid token
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: "bad-token", NewPassword: "NewPassword123!"}, "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	// Wrong token type (access token passed as reset token)
	accTok, _ := jwtMgr.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeAccess, time.Hour)
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: accTok, NewPassword: "NewPassword123!"}, "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for wrong token type, got %v", err)
	}
	// Missing user in token
	ghostResetTok, _ := jwtMgr.Issue(999999, models.RoleUser, "ghost@ex.com", jwt.TokenTypeReset, time.Hour)
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: ghostResetTok, NewPassword: "NewPassword123!"}, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Success
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTok, NewPassword: "NewPassword123!"}, "1.1.1.1"); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	// Replay used reset token (single use)
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTok, NewPassword: "NewPassword123!"}, "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on replayed reset token, got %v", err)
	}

	// 3. ChangePassword
	// User not found
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: 999999, OldPassword: "NewPassword123!", NewPassword: "BrandNewPwd123!"}, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Wrong old password
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: "WrongOldPassword1!", NewPassword: "BrandNewPwd123!"}, "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// Weak new password
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: "NewPassword123!", NewPassword: "weak"}, "1.1.1.1"); !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak, got %v", err)
	}
	// Success
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: "NewPassword123!", NewPassword: "BrandNewPwd123!"}, "1.1.1.1"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// 4. SetPassword
	// User not found
	if err := svc.SetPassword(ctx, 999999, "FirstPass123!", "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Password already set
	if err := svc.SetPassword(ctx, u.ID, "FirstPass123!", "1.1.1.1"); !errors.Is(err, ErrPasswordAlreadySet) {
		t.Fatalf("expected ErrPasswordAlreadySet, got %v", err)
	}
	// User without password (OAuth-only)
	oauthUser := &models.User{Username: "oauth_only", Email: "oauth@ex.com", Password: "", Role: models.RoleUser, IsActive: true}
	_ = userRepo.Create(ctx, oauthUser)
	if err := svc.SetPassword(ctx, oauthUser.ID, "FirstPass123!", "1.1.1.1"); err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	// 5. VerifyEmail
	verifyTok, _ := jwtMgr.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeEmailVerify, time.Hour)
	// Wrong token type
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: accTok}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for wrong token type, got %v", err)
	}
	// Missing user
	ghostVerifyTok, _ := jwtMgr.Issue(999999, models.RoleUser, "ghost@ex.com", jwt.TokenTypeEmailVerify, time.Hour)
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: ghostVerifyTok}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Success
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: verifyTok}); err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	// Replay token
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: verifyTok}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on replayed verify token, got %v", err)
	}

	// 6. RequestChangeEmail & ConfirmChangeEmail
	// User not found
	if err := svc.RequestChangeEmail(ctx, 999999, ChangeEmailRequestInput{Password: "BrandNewPwd123!", NewEmail: "new@ex.com"}, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Invalid password
	if err := svc.RequestChangeEmail(ctx, u.ID, ChangeEmailRequestInput{Password: "WrongPwd!", NewEmail: "new@ex.com"}, "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// Same email
	if err := svc.RequestChangeEmail(ctx, u.ID, ChangeEmailRequestInput{Password: "BrandNewPwd123!", NewEmail: u.Email}, "1.1.1.1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for same email, got %v", err)
	}
	// Disposable email
	if err := svc.RequestChangeEmail(ctx, u.ID, ChangeEmailRequestInput{Password: "BrandNewPwd123!", NewEmail: "bad@mailinator.com"}, "1.1.1.1"); !errors.Is(err, ErrDisposableEmail) {
		t.Fatalf("expected ErrDisposableEmail, got %v", err)
	}
	// Email exists
	if err := svc.RequestChangeEmail(ctx, u.ID, ChangeEmailRequestInput{Password: "BrandNewPwd123!", NewEmail: oauthUser.Email}, "1.1.1.1"); !errors.Is(err, ErrEmailExists) {
		t.Fatalf("expected ErrEmailExists, got %v", err)
	}
	// Valid request
	if err := svc.RequestChangeEmail(ctx, u.ID, ChangeEmailRequestInput{Password: "BrandNewPwd123!", NewEmail: "fresh_email@ex.com"}, "1.1.1.1"); err != nil {
		t.Fatalf("RequestChangeEmail failed: %v", err)
	}
	// Confirm with invalid token
	if err := svc.ConfirmChangeEmail(ctx, "bad-token", "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}

	// 7. CompleteMFALogin & CheckMFAOrIssueTokens
	// CompleteMFALogin without totpValidator
	svcNoTOTPVal := &AuthService{totpValidator: nil}
	if _, _, err := svcNoTOTPVal.CompleteMFALogin(ctx, CompleteMFALoginInput{UserID: u.ID, Code: "123456"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken when validator is nil, got %v", err)
	}
	// CompleteMFALogin invalid code
	_, _, err = svc.CompleteMFALogin(ctx, CompleteMFALoginInput{UserID: u.ID, Code: "000000", IP: "1.1.1.1"})
	if !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}
	// CompleteMFALogin success
	totpVal.err = nil
	pair, prof, err := svc.CompleteMFALogin(ctx, CompleteMFALoginInput{UserID: u.ID, Code: "123456", IP: "1.1.1.1", UA: "GoTest"})
	if err != nil {
		t.Fatalf("CompleteMFALogin failed: %v", err)
	}
	if pair.AccessToken == "" || prof.Email != u.Email {
		t.Fatalf("CompleteMFALogin returned unexpected pair: %+v", pair)
	}

	// CheckMFAOrIssueTokens without TOTP enabled -> full tokens
	p1, prof1, mfaPending, err := svc.CheckMFAOrIssueTokens(ctx, u, "1.1.1.1", "GoTest", "")
	if err != nil || mfaPending != nil || p1.AccessToken == "" || prof1.Email != u.Email {
		t.Fatalf("CheckMFAOrIssueTokens without TOTP device failed: %v", err)
	}

	// Enable TOTP for user
	_ = totpRepo.Upsert(ctx, &models.TOTPDevice{
		UserID:          u.ID,
		SecretEncrypted: "encrypted-secret",
		Enabled:         true,
	})
	// CheckMFAOrIssueTokens with TOTP enabled -> mfa_pending token
	p2, _, mfaPending2, err := svc.CheckMFAOrIssueTokens(ctx, u, "1.1.1.1", "GoTest", "")
	if err != nil || mfaPending2 == nil || !mfaPending2.MFARequired || mfaPending2.MFAToken == "" || p2.AccessToken != "" {
		t.Fatalf("CheckMFAOrIssueTokens with TOTP enabled should return mfaPending: %+v", mfaPending2)
	}
}

func TestAuthService_Deactivate_And_EraseAccount(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
		&models.PasskeyCredential{},
		&models.OAuthIdentity{},
	)

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{MaxLoginAttempts: 5, BcryptCost: hash.MinCost}
	jwtCfg := config.JWTConfig{
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		ResetTTL:      time.Hour,
		VerifyTTL:     time.Hour,
		MFAPendingTTL: 5 * time.Minute,
	}
	notify := NewConsoleNotifier("noreply@example.com")
	totpVal := &mockTOTPValidator{err: nil}

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, config.RateLimitConfig{}, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		totpRepo, totpVal,
		WithSessionRepo(sessionRepo),
		WithAuthPasskeys(passkeyRepo),
		WithAuthOAuthIdents(oauthRepo),
	)

	hashedPwd, _ := hash.HashPassword("Password123!", hash.MinCost)
	u := &models.User{
		Username:        "deactivatetest",
		Email:           "deactivate@example.com",
		Password:        hashedPwd,
		FullName:        "Deactivate User",
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
		PwdVersion:      1,
	}
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}

	// 1. DeactivateAccount tests:
	// Missing user
	if err := svc.DeactivateAccount(ctx, 99999, "", "Password123!", "jti-1", "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Missing sudo or password
	if err := svc.DeactivateAccount(ctx, u.ID, "", "", "jti-1", "1.1.1.1"); !errors.Is(err, ErrSudoRequired) {
		t.Fatalf("expected ErrSudoRequired, got %v", err)
	}
	// Wrong password
	if err := svc.DeactivateAccount(ctx, u.ID, "", "WrongPassword", "jti-1", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// Valid sudo token
	sudoTok, _ := jwtMgr.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeSudo, 5*time.Minute)
	if err := svc.DeactivateAccount(ctx, u.ID, sudoTok, "", "jti-1", "1.1.1.1"); err != nil {
		t.Fatalf("DeactivateAccount with sudo token failed: %v", err)
	}
	// Check user is now inactive
	reloaded, _ := userRepo.FindByID(ctx, u.ID)
	if reloaded.IsActive {
		t.Fatalf("expected user to be inactive after deactivation")
	}

	// Reactivate for erase test
	reloaded.IsActive = true
	_ = userRepo.Update(ctx, reloaded)

	// Add passkey, totp, and oauth identity for this user
	_ = passkeyRepo.Create(ctx, &models.PasskeyCredential{
		UserID:       u.ID,
		CredentialID: []byte("cred-1"),
		PublicKey:    []byte("pub-1"),
		DisplayName:  "Key 1",
	})
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         u.ID,
		Provider:       "google",
		ProviderUserID: "google-sub-123",
	})

	// 2. EraseAccount tests:
	// Missing user
	if err := svc.EraseAccount(ctx, 99999, "", "Password123!", "jti-2", "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Invalid credentials
	if err := svc.EraseAccount(ctx, u.ID, "", "WrongPwd!", "jti-2", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// Valid password
	if err := svc.EraseAccount(ctx, u.ID, "", "Password123!", "jti-2", "1.1.1.1"); err != nil {
		t.Fatalf("EraseAccount failed: %v", err)
	}
	// Verify erased state
	erasedUser, _ := userRepo.FindByID(ctx, u.ID)
	if erasedUser.Password != "" || erasedUser.IsActive || !strings.HasPrefix(erasedUser.Email, "deleted_") {
		t.Fatalf("erased user state invalid: %+v", erasedUser)
	}
	// Verify oauth identity and passkeys deleted/revoked
	oauths, _ := oauthRepo.FindByUserIDAndProvider(ctx, u.ID, "google")
	if oauths != nil {
		t.Fatalf("expected oauth identities to be purged")
	}
	pks, _ := passkeyRepo.ListByUser(ctx, u.ID, false)
	if len(pks) != 0 {
		t.Fatalf("expected active passkeys to be 0 after erase")
	}
}

func TestAuthService_RefreshBranches(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
		&models.TOTPDevice{},
	)

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{MaxLoginAttempts: 5, BcryptCost: hash.MinCost}
	jwtCfg := config.JWTConfig{
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		ResetTTL:      time.Hour,
		VerifyTTL:     time.Hour,
		MFAPendingTTL: 5 * time.Minute,
	}
	notify := NewConsoleNotifier("noreply@example.com")
	totpVal := &mockTOTPValidator{err: nil}

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, config.RateLimitConfig{}, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		totpRepo, totpVal,
		WithSessionRepo(sessionRepo),
	)

	hashedPwd, _ := hash.HashPassword("Password123!", hash.MinCost)
	u := &models.User{
		Username:        "refresher",
		Email:           "refresher@example.com",
		Password:        hashedPwd,
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
		PwdVersion:      1,
	}
	_ = userRepo.Create(ctx, u)

	// 1. Missing token
	if _, err := svc.Refresh(ctx, "nonexistent-token", "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for missing token, got %v", err)
	}

	// 2. Revoked token without SessionID (legacy reuse)
	rawTokLegacy := "legacy-refresh-raw-12345"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokLegacy),
		UserID:    u.ID,
		Revoked:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := svc.Refresh(ctx, rawTokLegacy, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for revoked legacy token, got %v", err)
	}

	// 3. Expired token
	rawTokExpired := "expired-refresh-raw-12345"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokExpired),
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if _, err := svc.Refresh(ctx, rawTokExpired, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}

	// 4. Inactive user token
	uInactive := &models.User{
		Username: "inactive_user",
		Email:    "inactive@example.com",
		Password: hashedPwd,
	}
	_ = userRepo.Create(ctx, uInactive)
	db.Model(uInactive).Update("is_active", false)
	rawTokInactive := "inactive-user-token"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokInactive),
		UserID:    uInactive.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := svc.Refresh(ctx, rawTokInactive, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for inactive user, got %v", err)
	}

	// 5. Token with SessionID but session missing
	rawTokMissingSess := "missing-sess-token"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokMissingSess),
		UserID:    u.ID,
		SessionID: "nonexistent-sess-id",
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := svc.Refresh(ctx, rawTokMissingSess, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken when session missing, got %v", err)
	}

	// 6. Token with revoked session
	sessRevoked := &models.Session{
		ID:        "sess-revoked-123",
		UserID:    u.ID,
		Revoked:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = sessionRepo.Create(ctx, sessRevoked)
	rawTokRevokedSess := "revoked-sess-token"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokRevokedSess),
		UserID:    u.ID,
		SessionID: sessRevoked.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := svc.Refresh(ctx, rawTokRevokedSess, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for revoked session token, got %v", err)
	}

	// 7. Token with expired session
	sessExpired := &models.Session{
		ID:        "sess-expired-123",
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	_ = sessionRepo.Create(ctx, sessExpired)
	rawTokExpiredSess := "expired-sess-token"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokExpiredSess),
		UserID:    u.ID,
		SessionID: sessExpired.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := svc.Refresh(ctx, rawTokExpiredSess, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for expired session token, got %v", err)
	}

	// 8. Revoked token with SessionID (session-family reuse isolation)
	sessActive := &models.Session{
		ID:        "sess-active-reuse",
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = sessionRepo.Create(ctx, sessActive)
	rawTokReusedSess := "reused-sess-token"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokReusedSess),
		UserID:    u.ID,
		SessionID: sessActive.ID,
		Revoked:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := svc.Refresh(ctx, rawTokReusedSess, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for reused session token, got %v", err)
	}
	// Verify session was killed by reuse containment
	killedSess, _ := sessionRepo.FindByID(ctx, sessActive.ID)
	if killedSess == nil || !killedSess.Revoked {
		t.Fatalf("expected session to be revoked after reuse containment")
	}

	// 9. Successful refresh inside session family
	sessValid := &models.Session{
		ID:        "sess-valid-family",
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = sessionRepo.Create(ctx, sessValid)
	rawTokValid := "valid-refresh-token"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(rawTokValid),
		UserID:    u.ID,
		SessionID: sessValid.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	newPair, err := svc.Refresh(ctx, rawTokValid, "1.1.1.1", "GoTest/1.0")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if newPair.AccessToken == "" || newPair.RefreshToken == "" {
		t.Fatalf("expected valid token pair, got %+v", newPair)
	}
}

func TestAuthService_SetPassword_Branches(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
	)
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{MaxLoginAttempts: 5, BcryptCost: hash.MinCost}
	jwtCfg := config.JWTConfig{
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	}
	notify := NewConsoleNotifier("noreply@example.com")

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, config.RateLimitConfig{}, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithMinPasswordScore(3),
	)

	// User not found
	if err := svc.SetPassword(ctx, 99999, "ComplexPass123!", "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	// User with password already set
	hashedPwd, _ := hash.HashPassword("InitialPwd123!", hash.MinCost)
	u := &models.User{
		Username:        "setpwduser",
		Email:           "setpwd@example.com",
		Password:        hashedPwd,
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = userRepo.Create(ctx, u)
	if err := svc.SetPassword(ctx, u.ID, "ComplexPass123!", "1.1.1.1"); !errors.Is(err, ErrPasswordAlreadySet) {
		t.Fatalf("expected ErrPasswordAlreadySet, got %v", err)
	}

	// User without password (OAuth account)
	oauthUser := &models.User{
		Username:        "oauthuser_nopwd",
		Email:           "oauth_nopwd@example.com",
		Password:        "",
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = userRepo.Create(ctx, oauthUser)

	// Weak password
	if err := svc.SetPassword(ctx, oauthUser.ID, "weak", "1.1.1.1"); err == nil {
		t.Fatal("expected validation error on weak password")
	}

	// Valid password set
	if err := svc.SetPassword(ctx, oauthUser.ID, "SuperSecurePwd123!", "1.1.1.1"); err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	reloaded, _ := userRepo.FindByID(ctx, oauthUser.ID)
	if reloaded.Password == "" || !hash.CheckPassword(reloaded.Password, "SuperSecurePwd123!") {
		t.Fatal("password was not properly updated")
	}
}

func TestOAuthService_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.User{}, &models.OAuthIdentity{}, &models.PasskeyCredential{}, &models.AuditLog{})

	userRepo := repositories.NewUserRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)
	notify := &mockNotifier{}
	issuer := &mockTokenIssuer{}
	verifier := &mockGoogleIDTokenVerifier{}
	client := &mockGoogleOAuthClient{authURL: "https://accounts.google.com/o/oauth2/v2/auth"}

	svc := NewOAuthService(
		userRepo, oauthRepo, memStore, issuer, verifier, client,
		WithOAuthNotifier(notify),
		WithOAuthAudits(auditRepo),
		WithOAuthPasskeys(passkeyRepo),
	)

	// 1. BeginLogin: nil client
	svcNilClient := NewOAuthService(userRepo, oauthRepo, memStore, issuer, verifier, nil)
	s, u, err := svcNilClient.BeginLogin(ctx)
	if err != nil || s != "" || u != "" {
		t.Fatalf("BeginLogin with nil client should return empty strings and nil err: s=%q, u=%q, err=%v", s, u, err)
	}

	// BeginLogin: active client
	state, authURL, err := svc.BeginLogin(ctx)
	if err != nil || state == "" || authURL == "" {
		t.Fatalf("BeginLogin failed: state=%q, authURL=%q, err=%v", state, authURL, err)
	}

	// 2. ConsumeState
	// Empty state
	if _, err := svc.ConsumeState(ctx, ""); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid on empty state, got %v", err)
	}
	// Missing state
	if _, err := svc.ConsumeState(ctx, "nonexistent-state"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid on nonexistent state, got %v", err)
	}
	// Corrupt JSON in store
	memStore.Set(oauthChallengeKey("corrupt"), "not-valid-json", time.Minute)
	if _, err := svc.ConsumeState(ctx, "corrupt"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid on corrupt state, got %v", err)
	}
	// Valid state
	ch, err := svc.ConsumeState(ctx, state)
	if err != nil || ch.Verifier == "" || ch.Nonce == "" {
		t.Fatalf("ConsumeState failed: ch=%+v, err=%v", ch, err)
	}
	// Replay state
	if _, err := svc.ConsumeState(ctx, state); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid on replayed state, got %v", err)
	}

	// 3. Unlink
	// User not found in identities
	if err := svc.Unlink(ctx, 99999, "google", "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound on missing identity, got %v", err)
	}

	// Create user with no password and no passkey
	testUser := &models.User{
		Username:        "oauth_unlink_user",
		Email:           "unlink@example.com",
		Password:        "",
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = userRepo.Create(ctx, testUser)
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         testUser.ID,
		Provider:       "google",
		ProviderUserID: "sub-unlink-1",
	})

	// Attempt unlink when it's the sole login method
	if err := svc.Unlink(ctx, testUser.ID, "google", "1.1.1.1"); !errors.Is(err, ErrCannotUnlinkOnlyMethod) {
		t.Fatalf("expected ErrCannotUnlinkOnlyMethod, got %v", err)
	}

	// Add passkey to user
	_ = passkeyRepo.Create(ctx, &models.PasskeyCredential{
		UserID:       testUser.ID,
		CredentialID: []byte("passkey-unlink-test"),
		PublicKey:    []byte("pubkey-bytes"),
		DisplayName:  "YubiKey",
	})

	// Now unlink succeeds with passkey present!
	if err := svc.Unlink(ctx, testUser.ID, "google", "1.1.1.1"); err != nil {
		t.Fatalf("Unlink with passkey present failed: %v", err)
	}

	// Confirm identity is gone
	ident, _ := oauthRepo.FindByUserIDAndProvider(ctx, testUser.ID, "google")
	if ident != nil {
		t.Fatal("expected identity to be deleted")
	}

	// Test Unlink with password present
	hashed, _ := hash.HashPassword("Password123!", hash.MinCost)
	testUser.Password = hashed
	_ = userRepo.Update(ctx, testUser)
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         testUser.ID,
		Provider:       "google",
		ProviderUserID: "sub-unlink-2",
	})
	if err := svc.Unlink(ctx, testUser.ID, "google", "1.1.1.1"); err != nil {
		t.Fatalf("Unlink with password present failed: %v", err)
	}
}

func TestPasskeyService_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.User{}, &models.PasskeyCredential{}, &models.AuditLog{})

	userRepo := repositories.NewUserRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)

	// 1. NewPasskeyService configurations
	// Empty RPID -> error
	if _, err := NewPasskeyService(passkeyRepo, userRepo, auditRepo, memStore, nil, PasskeyConfig{RPID: ""}); err == nil {
		t.Fatal("expected error with empty RPID")
	}
	// "indirect"
	svcIndirect, err := NewPasskeyService(passkeyRepo, userRepo, auditRepo, memStore, nil, PasskeyConfig{
		RPDisplayName: "TestRP", RPID: "localhost", RPOrigins: []string{"http://localhost:8080"}, AttestationPreference: "indirect",
	})
	if err != nil {
		t.Fatalf("NewPasskeyService indirect failed: %v", err)
	}
	if svcIndirect == nil {
		t.Fatal("expected non-nil service")
	}
	// "direct"
	svcDirect, err := NewPasskeyService(passkeyRepo, userRepo, auditRepo, memStore, nil, PasskeyConfig{
		RPDisplayName: "TestRP", RPID: "localhost", RPOrigins: []string{"http://localhost:8080"}, AttestationPreference: "direct",
	})
	if err != nil {
		t.Fatalf("NewPasskeyService direct failed: %v", err)
	}

	u := &models.User{
		Username: "passkey_tester",
		Email:    "passkey_tester@example.com",
		FullName: "Passkey Tester",
		IsActive: true,
	}
	_ = userRepo.Create(ctx, u)

	// 2. BeginRegistration
	// User not found
	if _, err := svcDirect.BeginRegistration(ctx, 99999, PasskeyBeginInput{DisplayName: "MacBook"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Valid user
	regOpts, err := svcDirect.BeginRegistration(ctx, u.ID, PasskeyBeginInput{DisplayName: "MacBook"})
	if err != nil {
		t.Fatalf("BeginRegistration failed: %v", err)
	}
	if regOpts == nil {
		t.Fatal("expected non-nil registration options")
	}

	// 3. BeginAuthentication
	// User not found
	if _, err := svcDirect.BeginAuthentication(ctx, 99999); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// User with no registered passkeys
	if _, err := svcDirect.BeginAuthentication(ctx, u.ID); err == nil {
		t.Fatal("expected error for user with no passkeys, got nil")
	}

	// 4. FinishAuthentication error branches
	// Nil tokens issuer
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/auth", nil)
	if _, err := svcDirect.FinishAuthentication(ctx, u.ID, req); !errors.Is(err, ErrPasskeyNotConfigured) {
		t.Fatalf("expected ErrPasskeyNotConfigured, got %v", err)
	}

	// With token issuer, but challenge missing
	issuerMock := &fakePasskeyIssuer{}
	svcWithTokens, _ := NewPasskeyService(passkeyRepo, userRepo, auditRepo, memStore, issuerMock, PasskeyConfig{
		RPDisplayName: "TestRP", RPID: "localhost", RPOrigins: []string{"http://localhost:8080"},
	})
	if _, err := svcWithTokens.FinishAuthentication(ctx, u.ID, req); !errors.Is(err, ErrPasskeyChallenge) {
		t.Fatalf("expected ErrPasskeyChallenge, got %v", err)
	}

	// 5. List and Revoke
	list, err := svcDirect.List(ctx, u.ID)
	if err != nil || len(list) != 0 {
		t.Fatalf("expected empty list, got len=%d, err=%v", len(list), err)
	}
	// Revoke nonexistent
	if err := svcDirect.Revoke(ctx, 9999, u.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound on Revoke, got %v", err)
	}
}

func TestWebhookService_EnqueueAndDeliver(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.WebhookEndpoint{}, &models.WebhookDelivery{})
	repo := repositories.NewWebhookRepository(db)

	svc := NewWebhookService(repo)

	// 1. URL validation
	if err := svc.ValidateURL("not-a-url"); !errors.Is(err, ErrInvalidWebhookURL) {
		t.Fatalf("expected ErrInvalidWebhookURL, got %v", err)
	}
	if err := svc.ValidateURL("ftp://example.com"); !errors.Is(err, ErrInvalidWebhookURL) {
		t.Fatalf("expected ErrInvalidWebhookURL for ftp, got %v", err)
	}

	// Blocked SSRF check (without allowLocalhost)
	if err := svc.ValidateURL("http://127.0.0.1:8080/hook"); !errors.Is(err, ErrWebhookSSRFBlocked) {
		t.Fatalf("expected ErrWebhookSSRFBlocked for localhost, got %v", err)
	}

	// Allow localhost
	svc.SetAllowLocalhost(true)
	if err := svc.ValidateURL("http://127.0.0.1:8080/hook"); err != nil {
		t.Fatalf("expected nil when localhost is allowed, got %v", err)
	}

	// 2. RegisterEndpoint
	// When invalid URL
	svc.SetAllowLocalhost(false)
	if _, err := svc.RegisterEndpoint(ctx, "tenant-1", "http://127.0.0.1:8080/hook", "user.created"); !errors.Is(err, ErrWebhookSSRFBlocked) {
		t.Fatalf("expected ErrWebhookSSRFBlocked, got %v", err)
	}
	svc.SetAllowLocalhost(true)
	ep, err := svc.RegisterEndpoint(ctx, "tenant-1", "http://localhost:8080/hook", "user.created,user.updated")
	if err != nil {
		t.Fatalf("RegisterEndpoint failed: %v", err)
	}
	if ep.ID == "" || ep.Secret == "" {
		t.Fatalf("endpoint ID or Secret empty: %+v", ep)
	}

	// 3. EnqueueEvent
	// No endpoints match
	if err := svc.EnqueueEvent(ctx, "tenant-1", "nonexistent.event", map[string]string{"foo": "bar"}); err != nil {
		t.Fatalf("EnqueueEvent for unmatched event failed: %v", err)
	}
	// Matching event
	if err := svc.EnqueueEvent(ctx, "tenant-1", "user.created", map[string]string{"foo": "bar"}); err != nil {
		t.Fatalf("EnqueueEvent failed: %v", err)
	}
	deliveries, err := repo.GetPendingDeliveries(ctx, 10)
	if err != nil || len(deliveries) == 0 {
		t.Fatalf("expected pending delivery, got len=%d, err=%v", len(deliveries), err)
	}

	// 4. DeliverOne
	d := &deliveries[0]

	// 4a. Target server returns 200 OK
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Signature-256") == "" || r.Header.Get("X-Event") != d.Event {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srvOK.Close()

	if err := svc.DeliverOne(ctx, d, ep.Secret, srvOK.URL); err != nil {
		t.Fatalf("DeliverOne with 200 OK failed: %v", err)
	}

	// 4b. Target server returns 500 Error (< 5 attempts -> pending)
	srvFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvFail.Close()

	d2 := &models.WebhookDelivery{
		ID:         "delivery-fail-1",
		EndpointID: ep.ID,
		Event:      "user.created",
		Payload:    `{"test": true}`,
		Attempts:   0,
	}
	_ = repo.CreateDelivery(ctx, d2)
	if err := svc.DeliverOne(ctx, d2, ep.Secret, srvFail.URL); err == nil {
		t.Fatal("expected error on 500 status")
	}

	// 4c. Target server returns 500 Error (attempt >= 5 -> failed)
	d2.Attempts = 4
	if err := svc.DeliverOne(ctx, d2, ep.Secret, srvFail.URL); err == nil {
		t.Fatal("expected error on final retry")
	}

	// 4d. DeliverOne with invalid URL
	if err := svc.DeliverOne(ctx, d, ep.Secret, "not-a-url"); err == nil {
		t.Fatal("expected error with invalid URL")
	}
}

func TestTOTPService_Disable_And_GetMethods_Extra(t *testing.T) {
	repo := newMockTOTPRepo()
	users := newMockUserRepo()
	notify := &mockNotifier{}
	u := &models.User{
		ID:       50,
		Email:    "extra_totp@example.com",
		Password: "hashed-password",
	}
	h, _ := hash.HashPassword("Password123", hash.MinCost)
	u.Password = h
	_ = users.Create(context.Background(), u)

	svc := newTestTOTPService(t, repo, nil, nil)
	svc.users = users
	svc.notify = notify

	ctx := context.Background()

	// 1. Disable when device is not found / not enabled (idempotent)
	if err := svc.Disable(ctx, u.ID, "", "Password123", "123456", "1.1.1.1"); err != nil {
		t.Fatalf("Disable on non-existent device should return nil, got %v", err)
	}

	// Enable TOTP for user
	enableAndVerify(t, svc, u.ID)

	// 2. Disable with valid Sudo Token
	sudoClaimsToken, _ := testJWTManager.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeSudo, 5*time.Minute)
	if err := svc.Disable(ctx, u.ID, sudoClaimsToken, "", "", "1.1.1.1"); err != nil {
		t.Fatalf("Disable with valid sudo token failed: %v", err)
	}

	// 3. Re-enable to test fallback branches
	_, codes := enableAndVerify(t, svc, u.ID)

	// Missing user in fallback (device enabled in repo, but user missing from users repo)
	_ = repo.Upsert(ctx, &models.TOTPDevice{UserID: 99999, Enabled: true, SecretEncrypted: "enc"})
	if err := svc.Disable(ctx, 99999, "", "Password123", codes[0], "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Empty code in fallback
	if err := svc.Disable(ctx, u.ID, "", "Password123", "", "1.1.1.1"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode for empty code, got %v", err)
	}
	// Empty password in fallback
	if err := svc.Disable(ctx, u.ID, "", "", codes[0], "1.1.1.1"); !errors.Is(err, ErrSudoRequired) {
		t.Fatalf("expected ErrSudoRequired for empty password, got %v", err)
	}

	// 4. GetMFAMethods with Passkeys
	fakePasskeys := newFakePasskeyRepo()
	_ = fakePasskeys.Create(ctx, &models.PasskeyCredential{
		UserID:       u.ID,
		CredentialID: []byte("passkey-test-id"),
		DisplayName:  "USB Key",
	})
	svc.passkeys = fakePasskeys

	mfaRes, err := svc.GetMFAMethods(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetMFAMethods failed: %v", err)
	}
	if !mfaRes.TOTPEnabled || mfaRes.PasskeysCount != 1 || mfaRes.DefaultMethod != "passkey" {
		t.Fatalf("unexpected GetMFAMethods result: %+v", mfaRes)
	}

	// 5. ViewRecoveryCodes error branches
	// Non-enabled device
	if _, err := svc.ViewRecoveryCodes(ctx, 999999, "123456"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode for missing device, got %v", err)
	}
	// Code length != 6
	if _, err := svc.ViewRecoveryCodes(ctx, u.ID, "12345"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode for code length != 6, got %v", err)
	}

	// 6. RegenerateRecoveryCodes for missing device
	if _, err := svc.RegenerateRecoveryCodes(ctx, 999999); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode for missing device on regenerate, got %v", err)
	}
}

func TestAuthService_Logout_And_LogoutAll_Comprehensive(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
	)
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{MaxLoginAttempts: 5, BcryptCost: hash.MinCost}
	jwtCfg := config.JWTConfig{
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	}
	notify := NewConsoleNotifier("noreply@example.com")

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, config.RateLimitConfig{}, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithSessionRepo(sessionRepo),
	)

	u := &models.User{
		Username: "logoutuser",
		Email:    "logout@example.com",
		Password: "hashed-password",
		IsActive: true,
	}
	_ = userRepo.Create(ctx, u)

	// 1. Logout: unknown / empty token -> idempotent success
	if err := svc.Logout(ctx, "nonexistent-tok", "jti-logout-1", "1.1.1.1"); err != nil {
		t.Fatalf("Logout with nonexistent token should succeed: %v", err)
	}

	// 2. Logout: already revoked token -> idempotent success
	revokedRaw := "already-revoked-tok"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(revokedRaw),
		UserID:    u.ID,
		Revoked:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err := svc.Logout(ctx, revokedRaw, "", "1.1.1.1"); err != nil {
		t.Fatalf("Logout with revoked token should succeed: %v", err)
	}

	// 3. Logout: active token with session and accessJTI
	sess := &models.Session{
		ID:        "sess-logout-123",
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = sessionRepo.Create(ctx, sess)

	activeRaw := "active-logout-tok"
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: hash.HashToken(activeRaw),
		UserID:    u.ID,
		SessionID: sess.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	if err := svc.Logout(ctx, activeRaw, "jti-active-logout", "1.1.1.1"); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Verify token and session revoked
	tokReload, _ := tokenRepo.FindByHash(ctx, hash.HashToken(activeRaw))
	if tokReload == nil || !tokReload.Revoked {
		t.Fatal("expected token to be revoked")
	}
	sessReload, _ := sessionRepo.FindByID(ctx, sess.ID)
	if sessReload == nil || !sessReload.Revoked {
		t.Fatal("expected session to be revoked")
	}

	// 4. LogoutAll
	if err := svc.LogoutAll(ctx, u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("LogoutAll failed: %v", err)
	}

	// 5. GetUserAuditLog
	// With nil audits
	svcNilAudit := &AuthService{audits: nil}
	items, total, err := svcNilAudit.GetUserAuditLog(ctx, u.ID, 1, 10)
	if err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("GetUserAuditLog with nil audit failed: len=%d, total=%d, err=%v", len(items), total, err)
	}

	// With active audits
	items, total, err = svc.GetUserAuditLog(ctx, u.ID, 1, 10)
	if err != nil || total == 0 || len(items) == 0 {
		t.Fatalf("GetUserAuditLog failed: len=%d, total=%d, err=%v", len(items), total, err)
	}

	// 6. RevokeSession
	// Legacy mode (sessions == nil)
	svcLegacy := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, config.RateLimitConfig{}, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	// Invalid ID
	if err := svcLegacy.RevokeSession(ctx, "bad-id", u.ID, "1.1.1.1"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for bad-id, got %v", err)
	}
	// Missing token in legacy mode
	if err := svcLegacy.RevokeSession(ctx, "99999", u.ID, "1.1.1.1"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for missing token, got %v", err)
	}
	// Active token in legacy mode
	// #nosec G101 -- test mock token hash, not real credentials
	legacyTok := &models.RefreshToken{
		TokenHash: "hash-legacy-sess",
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = tokenRepo.Create(ctx, legacyTok)
	if err := svcLegacy.RevokeSession(ctx, fmt.Sprintf("%d", legacyTok.ID), u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("RevokeSession in legacy mode failed: %v", err)
	}

	// Modern mode (sessions != nil)
	// Not found / wrong user
	if err := svc.RevokeSession(ctx, "nonexistent-sess", u.ID, "1.1.1.1"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
	sessToRevoke := &models.Session{
		ID:        "sess-to-revoke",
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = sessionRepo.Create(ctx, sessToRevoke)
	if err := svc.RevokeSession(ctx, sessToRevoke.ID, u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
}

func TestAuthService_ConfirmChangeEmail_Comprehensive(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
	)
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{MaxLoginAttempts: 5, BcryptCost: hash.MinCost}
	jwtCfg := config.JWTConfig{
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	}
	notify := NewConsoleNotifier("noreply@example.com")

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, config.RateLimitConfig{}, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithSessionRepo(sessionRepo),
	)

	u1 := &models.User{
		Username: "changeuser1",
		Email:    "u1@example.com",
		Password: "password",
		IsActive: true,
	}
	_ = userRepo.Create(ctx, u1)

	u2 := &models.User{
		Username: "changeuser2",
		Email:    "u2@example.com",
		Password: "password",
		IsActive: true,
	}
	_ = userRepo.Create(ctx, u2)

	// 1. Invalid token / missing store
	if err := svc.ConfirmChangeEmail(ctx, "", "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on empty token, got %v", err)
	}
	if err := svc.ConfirmChangeEmail(ctx, "not-found", "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on missing token, got %v", err)
	}

	// 2. Malformed payload
	memStore.Set("change_email:bad-parts", "only:two", time.Hour)
	if err := svc.ConfirmChangeEmail(ctx, "bad-parts", "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on bad parts, got %v", err)
	}

	memStore.Set("change_email:bad-uid", "notanumber:old@ex.com:new@ex.com", time.Hour)
	if err := svc.ConfirmChangeEmail(ctx, "bad-uid", "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on bad uid, got %v", err)
	}

	// 3. Collision with another user's email
	memStore.Set("change_email:colliding", fmt.Sprintf("%d:%s:%s", u1.ID, u1.Email, u2.Email), time.Hour)
	if err := svc.ConfirmChangeEmail(ctx, "colliding", "1.1.1.1"); !errors.Is(err, ErrEmailExists) {
		t.Fatalf("expected ErrEmailExists on colliding email, got %v", err)
	}

	// 4. Missing user
	memStore.Set("change_email:ghost", "99999:old@ex.com:ghost@ex.com", time.Hour)
	if err := svc.ConfirmChangeEmail(ctx, "ghost", "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound on missing user, got %v", err)
	}

	// 5. Success
	newEmail := "fresh_new_email@example.com"
	memStore.Set("change_email:valid", fmt.Sprintf("%d:%s:%s", u1.ID, u1.Email, newEmail), time.Hour)
	if err := svc.ConfirmChangeEmail(ctx, "valid", "1.1.1.1"); err != nil {
		t.Fatalf("ConfirmChangeEmail failed: %v", err)
	}

	reloaded, _ := userRepo.FindByID(ctx, u1.ID)
	if reloaded.Email != newEmail || !reloaded.IsEmailVerified {
		t.Fatalf("user email was not updated properly: %+v", reloaded)
	}
}

func TestAuthService_InternalHelpers_Comprehensive(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.User{}, &models.UsedToken{}, &models.RefreshToken{}, &models.Session{}, &models.AuditLog{})
	userRepo := repositories.NewUserRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)

	rlCfg := config.RateLimitConfig{
		VerifyResendGlobalMax:    2,
		VerifyResendGlobalWindow: time.Minute,
		VerifyResendPerIPMax:     2,
		VerifyResendPerIPWindow:  time.Minute,
		VerifyResendPerEmailMax:  2,
		VerifyResendWindow:       time.Minute,
	}
	svc := &AuthService{
		store:      memStore,
		rlCfg:      rlCfg,
		usedTokens: usedTokenRepo,
		tokens:     tokenRepo,
		sessions:   sessionRepo,
		audits:     auditRepo,
		users:      userRepo,
	}

	// 1. shouldThrottleDuplicateRegisterAlert
	// Without store -> false
	svcNoStore := &AuthService{}
	if svcNoStore.shouldThrottleDuplicateRegisterAlert("a@b.com", "1.1.1.1") {
		t.Fatal("expected false without store")
	}

	// First 2 calls pass
	if svc.shouldThrottleDuplicateRegisterAlert("test@ex.com", "1.2.3.4") {
		t.Fatal("call 1 should not throttle")
	}
	if svc.shouldThrottleDuplicateRegisterAlert("test@ex.com", "1.2.3.4") {
		t.Fatal("call 2 should not throttle")
	}
	// 3rd call throttles by per-email and global
	if !svc.shouldThrottleDuplicateRegisterAlert("test@ex.com", "1.2.3.4") {
		t.Fatal("call 3 should throttle")
	}

	// 2. resolveLocation
	if loc := svcNoStore.resolveLocation(ctx, "1.1.1.1"); loc != geo.UnknownLocation {
		t.Fatalf("expected %s, got %s", geo.UnknownLocation, loc)
	}
	if loc := svc.resolveLocation(ctx, ""); loc != geo.UnknownLocation {
		t.Fatalf("expected %s for empty IP, got %s", geo.UnknownLocation, loc)
	}
	mockGeo := geo.NewNoOpResolver()
	svc.geo = mockGeo
	if loc := svc.resolveLocation(ctx, "8.8.8.8"); loc != geo.UnknownLocation {
		t.Fatalf("expected %s for noop geo, got %s", geo.UnknownLocation, loc)
	}

	// 3. markTokenUsed, jtiStoreTTL, markTokenDurable, consumeSingleUseToken
	if !svcNoStore.markTokenUsed("jti-1", time.Hour) {
		t.Fatal("expected true without store")
	}
	if !svc.markTokenUsed("jti-1", time.Hour) {
		t.Fatal("first mark should succeed")
	}
	if svc.markTokenUsed("jti-1", time.Hour) {
		t.Fatal("second mark should fail (already set)")
	}

	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")
	tok, _ := jwtMgr.Issue(1, "user", "test@ex.com", jwt.TokenTypeAccess, 30*time.Minute)
	claims, _ := jwtMgr.Verify(tok)
	if ttl := svc.jtiStoreTTL(claims); ttl <= 0 {
		t.Fatalf("expected positive ttl, got %v", ttl)
	}
	if ttl := svc.jtiStoreTTL(nil); ttl != 24*time.Hour {
		t.Fatalf("expected 24h default ttl, got %v", ttl)
	}

	if err := svcNoStore.markTokenDurable(ctx, "jti", "verify", 1, time.Now()); err != nil {
		t.Fatalf("expected nil without usedTokens repo, got %v", err)
	}
	if err := svc.markTokenDurable(ctx, "jti-durable", "verify", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("markTokenDurable failed: %v", err)
	}

	// consumeSingleUseToken
	if !svc.consumeSingleUseToken(ctx, "fresh-jti-consume", time.Hour) {
		t.Fatal("expected true on fresh token")
	}
	if svc.consumeSingleUseToken(ctx, "fresh-jti-consume", time.Hour) {
		t.Fatal("expected false on replayed token")
	}

	// 4. applyCredentialChange fallback with mockUserRepo
	mockUsers := newMockUserRepo()
	mockTokens := tokenRepo
	uMock := &models.User{
		Username: "mockuser",
		Email:    "mock@ex.com",
		Password: "old-password",
	}
	_ = mockUsers.Create(ctx, uMock)
	svcMock := &AuthService{
		users:  mockUsers,
		tokens: mockTokens,
		audits: auditRepo,
		store:  memStore,
	}
	if err := svcMock.applyCredentialChange(ctx, uMock, "new-hashed-password"); err != nil {
		t.Fatalf("applyCredentialChange fallback failed: %v", err)
	}
}

func TestOAuthService_HandleCallback_Branches(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.User{}, &models.OAuthIdentity{}, &models.PasskeyCredential{}, &models.AuditLog{})

	userRepo := repositories.NewUserRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)
	notify := &mockNotifier{}
	issuer := &mockTokenIssuer{
		pair: TokenPair{AccessToken: "acc-123", RefreshToken: "ref-123"},
	}
	verifier := &mockGoogleIDTokenVerifier{}
	client := &mockGoogleOAuthClient{
		authURL: "https://accounts.google.com/o/oauth2/v2/auth",
		token:   exchangeToken("fake-id-token"),
	}

	svc := NewOAuthService(
		userRepo, oauthRepo, memStore, issuer, verifier, client,
		WithOAuthNotifier(notify),
		WithOAuthAudits(auditRepo),
		WithOAuthPasskeys(passkeyRepo),
	)

	// 1. State missing -> ErrOAuthStateInvalid
	if _, _, _, err := svc.HandleCallback(ctx, "code", "missing-state", "1.1.1.1", "GoTest"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid, got %v", err)
	}

	// 2. Client is nil -> ErrOAuthNotConfigured
	svcNoClient := NewOAuthService(userRepo, oauthRepo, memStore, issuer, verifier, nil)
	memStore.Set(oauthChallengeKey("st-1"), `{"verifier":"v1","nonce":"n1"}`, time.Minute)
	if _, _, _, err := svcNoClient.HandleCallback(ctx, "code", "st-1", "1.1.1.1", "GoTest"); !errors.Is(err, ErrOAuthNotConfigured) {
		t.Fatalf("expected ErrOAuthNotConfigured, got %v", err)
	}

	// 3. Client Exchange error -> ErrOAuthCodeExchangeFailed
	client.err = errors.New("exchange network timeout")
	memStore.Set(oauthChallengeKey("st-2"), `{"verifier":"v2","nonce":"n2"}`, time.Minute)
	if _, _, _, err := svc.HandleCallback(ctx, "code", "st-2", "1.1.1.1", "GoTest"); !errors.Is(err, ErrOAuthCodeExchangeFailed) {
		t.Fatalf("expected ErrOAuthCodeExchangeFailed, got %v", err)
	}
	client.err = nil

	// 4. Nonce mismatch -> ErrOAuthTokenVerificationFailed
	verifier.claims = &GoogleIDTokenClaims{
		Sub:           "sub-123",
		Email:         "oauth_flow@example.com",
		EmailVerified: true,
		Nonce:         "wrong-nonce",
	}
	memStore.Set(oauthChallengeKey("st-3"), `{"verifier":"v3","nonce":"correct-nonce"}`, time.Minute)
	if _, _, _, err := svc.HandleCallback(ctx, "code", "st-3", "1.1.1.1", "GoTest"); !errors.Is(err, ErrOAuthTokenVerificationFailed) {
		t.Fatalf("expected ErrOAuthTokenVerificationFailed on nonce mismatch, got %v", err)
	}

	// 5. Email not verified -> ErrOAuthEmailNotVerified
	verifier.claims = &GoogleIDTokenClaims{
		Sub:           "sub-123",
		Email:         "oauth_flow@example.com",
		EmailVerified: false,
		Nonce:         "matching-nonce",
	}
	memStore.Set(oauthChallengeKey("st-4"), `{"verifier":"v4","nonce":"matching-nonce"}`, time.Minute)
	if _, _, _, err := svc.HandleCallback(ctx, "code", "st-4", "1.1.1.1", "GoTest"); !errors.Is(err, ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified, got %v", err)
	}

	// 6. User account exists but is unverified -> ErrOAuthEmailTaken
	unverifiedUser := &models.User{
		Username:        "unverified_local",
		Email:           "unverified@example.com",
		Password:        "hashed",
		IsEmailVerified: false,
		IsActive:        true,
	}
	_ = userRepo.Create(ctx, unverifiedUser)
	db.Model(unverifiedUser).Update("is_email_verified", false)

	verifier.claims = &GoogleIDTokenClaims{
		Sub:           "sub-takeover",
		Email:         "unverified@example.com",
		EmailVerified: true,
		Nonce:         "matching-nonce",
	}
	memStore.Set(oauthChallengeKey("st-5"), `{"verifier":"v5","nonce":"matching-nonce"}`, time.Minute)
	if _, _, _, err := svc.HandleCallback(ctx, "code", "st-5", "1.1.1.1", "GoTest"); !errors.Is(err, ErrOAuthEmailTaken) {
		t.Fatalf("expected ErrOAuthEmailTaken, got %v", err)
	}

	// 7. Successful new user provisioning and login
	verifier.claims = &GoogleIDTokenClaims{
		Sub:           "sub-fresh-google-user",
		Email:         "brandnewgoogle@example.com",
		EmailVerified: true,
		Name:          "Brand New",
		Nonce:         "matching-nonce",
	}
	memStore.Set(oauthChallengeKey("st-6"), `{"verifier":"v6","nonce":"matching-nonce"}`, time.Minute)
	pair, prof, mfa, err := svc.HandleCallback(ctx, "code", "st-6", "1.1.1.1", "GoTest")
	if err != nil {
		t.Fatalf("HandleCallback failed: %v", err)
	}
	if pair.AccessToken == "" || mfa != nil {
		t.Fatalf("unexpected token pair: %+v, mfa: %+v", pair, mfa)
	}
	_ = prof

	// 8. Re-login with existing linked identity
	memStore.Set(oauthChallengeKey("st-7"), `{"verifier":"v7","nonce":"matching-nonce"}`, time.Minute)
	pair2, _, _, err := svc.HandleCallback(ctx, "code", "st-7", "1.1.1.1", "GoTest")
	if err != nil || pair2.AccessToken == "" {
		t.Fatalf("HandleCallback for existing link failed: %v", err)
	}
}

func TestPasskey_TransportsAndClientIP(t *testing.T) {
	// transportsJSON
	if s := transportsJSON(nil); s != "[]" {
		t.Fatalf("expected [], got %s", s)
	}
	if s := transportsJSON([]protocol.AuthenticatorTransport{protocol.USB, protocol.NFC}); !strings.Contains(s, "usb") {
		t.Fatalf("expected usb in transports, got %s", s)
	}

	// clientIPFrom
	if ip := clientIPFrom(nil); ip != "" {
		t.Fatalf("expected empty for nil request, got %s", ip)
	}
	reqWithPort := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	reqWithPort.RemoteAddr = "192.168.1.50:54321"
	if ip := clientIPFrom(reqWithPort); ip != "192.168.1.50" {
		t.Fatalf("expected 192.168.1.50, got %s", ip)
	}
	reqNoPort := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	reqNoPort.RemoteAddr = "192.168.1.50"
	if ip := clientIPFrom(reqNoPort); ip != "192.168.1.50" {
		t.Fatalf("expected 192.168.1.50, got %s", ip)
	}
}

func TestTOTPService_Constructor_And_Options(t *testing.T) {
	repo := newMockTOTPRepo()
	users := newMockUserRepo()
	notify := &mockNotifier{}
	pks := newFakePasskeyRepo()
	enc := testEncryptor(t)

	// Zero-value config tests the defaults
	svc := NewTOTPService(
		repo, nil, nil, "Issuer", config.AuthConfig{}, enc, testJWTManager,
		WithTOTPUserRepo(users),
		WithTOTPNotifier(notify),
		WithTOTPPasskeys(pks),
	)
	if svc.cfg.TOTPMaxAttempts != 5 || svc.cfg.RecoveryCodeCount != 10 || svc.cfg.RecoveryCodeBytes != 16 {
		t.Fatalf("expected defaults to be populated, got %+v", svc.cfg)
	}
	if svc.users != users || svc.notify != notify || svc.passkeys != pks {
		t.Fatal("expected options to configure fields")
	}
}

func TestAsyncAuditWriter_Buffered(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.AuditLog{})
	repo := repositories.NewAuditRepository(db)

	// Sync mode writer
	syncCfg := config.AuditConfig{BufferSize: 0}
	wSync := NewAsyncAuditWriter(repo, repo, syncCfg)
	if n := wSync.Buffered(); n != 0 {
		t.Fatalf("expected 0 for sync writer, got %d", n)
	}
	wSync.Close()

	// Async mode writer
	asyncCfg := config.AuditConfig{
		BufferSize: 100,
		FlushBatch: 10,
	}
	wAsync := NewAsyncAuditWriter(repo, repo, asyncCfg)
	if n := wAsync.Buffered(); n != 0 {
		t.Fatalf("expected 0 initially, got %d", n)
	}
	wAsync.Close()
}

func TestSMTPNotifier_ValidationErrors(t *testing.T) {
	n := NewSMTPNotifier("localhost", "25", "noreply@example.com", "", "")
	ctx := context.Background()

	// Recipient header injection
	if err := n.send(ctx, "bad\nrecipient@example.com", "Subject", "Body"); err == nil {
		t.Fatal("expected error on recipient with newline")
	}

	// Subject header injection
	if err := n.send(ctx, "user@example.com", "Bad\r\nSubject", "Body"); err == nil {
		t.Fatal("expected error on subject with CRLF")
	}

	// Sender header injection
	nBadFrom := NewSMTPNotifier("localhost", "25", "bad\r\nfrom@example.com", "", "")
	if err := nBadFrom.send(ctx, "user@example.com", "Subject", "Body"); err == nil {
		t.Fatal("expected error on sender with CRLF")
	}

	// Not enabled
	nDisabled := NewSMTPNotifier("", "", "", "", "")
	if err := nDisabled.send(ctx, "user@example.com", "Subject", "Body"); err == nil {
		t.Fatal("expected error when SMTP is disabled")
	}
}

func TestGoogleIDTokenVerifier_EdgeCases(t *testing.T) {
	v := NewProductionGoogleVerifier("client-id-test")
	if v == nil || v.clientID != "client-id-test" {
		t.Fatalf("NewProductionGoogleVerifier failed: %+v", v)
	}
	// Invalid token should fail with ErrOAuthTokenVerificationFailed
	if _, err := v.Verify(context.Background(), "invalid.jwt.token"); !errors.Is(err, ErrOAuthTokenVerificationFailed) {
		t.Fatalf("expected ErrOAuthTokenVerificationFailed, got %v", err)
	}
}

func TestServices_Comprehensive_Push90(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
		&models.PasskeyCredential{},
		&models.OAuthIdentity{},
	)

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	authCfg := config.AuthConfig{
		MaxLoginAttempts:     5,
		RequireEmailVerified: true,
		BcryptCost:           hash.MinCost,
	}
	rlCfg := config.RateLimitConfig{
		RegisterPerIPMax:         10,
		RegisterWindow:           time.Minute,
		VerifyResendGlobalMax:    5,
		VerifyResendGlobalWindow: time.Minute,
		VerifyResendPerIPMax:     5,
		VerifyResendPerIPWindow:  time.Minute,
		VerifyResendPerEmailMax:  2,
		VerifyResendWindow:       time.Minute,
	}
	jwtCfg := config.JWTConfig{
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
		VerifyTTL:  time.Hour,
		ResetTTL:   time.Hour,
	}
	notify := &mockNotifier{}
	totpVal := &mockTOTPValidator{}

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		totpRepo, totpVal,
		WithSessionRepo(sessionRepo),
		WithAuthPasskeys(passkeyRepo),
	)

	// 1. Register edge cases
	// Register with duplicate username
	u1 := &models.User{
		Username:        "existing_user",
		Email:           "existing@example.com",
		Password:        "hashed",
		IsEmailVerified: true,
		IsActive:        true,
	}
	_ = userRepo.Create(ctx, u1)

	prof, err := svc.Register(ctx, RegisterInput{
		Username: "existing_user",
		Email:    "different_email@example.com",
		Password: "SecurePassword123!",
		IP:       "1.1.1.1",
	})
	if err != nil || prof.Username != "existing_user" {
		t.Fatalf("Register with duplicate username should return synthetic profile, got %+v, err=%v", prof, err)
	}

	// Register with notify failure
	notify.verifySendErr = errors.New("smtp connection failed")
	prof2, err := svc.Register(ctx, RegisterInput{
		Username: "user_notify_fail",
		Email:    "notify_fail@example.com",
		Password: "SecurePassword123!",
		IP:       "1.1.1.1",
	})
	if err != nil || prof2.Email != "notify_fail@example.com" {
		t.Fatalf("Register with notify failure should succeed with audit log, got err=%v", err)
	}
	notify.verifySendErr = nil

	// 2. Login edge cases
	// 2a. RequireEmailVerified is true, user is unverified
	unverifiedUser := &models.User{
		Username:        "unverified_login_user",
		Email:           "unverified_login@example.com",
		Password:        "hashed",
		IsEmailVerified: false,
		IsActive:        true,
	}
	h, _ := hash.HashPassword("Password123!", hash.MinCost)
	unverifiedUser.Password = h
	_ = userRepo.Create(ctx, unverifiedUser)
	db.Model(unverifiedUser).Update("is_email_verified", false)

	if _, _, _, err := svc.Login(ctx, LoginInput{Email: unverifiedUser.Email, Password: "Password123!"}, "1.1.1.1", "GoTest"); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	// 2b. User inactive
	inactiveUser := &models.User{
		Username:        "inactive_login_user",
		Email:           "inactive_login@example.com",
		Password:        h,
		IsEmailVerified: true,
		IsActive:        false,
	}
	_ = userRepo.Create(ctx, inactiveUser)
	db.Model(inactiveUser).Update("is_active", false)
	if _, _, _, err := svc.Login(ctx, LoginInput{Email: inactiveUser.Email, Password: "Password123!"}, "1.1.1.1", "GoTest"); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("expected ErrAccountDisabled, got %v", err)
	}

	// 2c. User locked
	lockedTime := time.Now().Add(time.Hour)
	lockedUser := &models.User{
		Username:        "locked_login_user",
		Email:           "locked_login@example.com",
		Password:        h,
		IsEmailVerified: true,
		IsActive:        true,
		LockedUntil:     &lockedTime,
	}
	_ = userRepo.Create(ctx, lockedUser)
	if _, _, _, err := svc.Login(ctx, LoginInput{Email: lockedUser.Email, Password: "Password123!"}, "1.1.1.1", "GoTest"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}

	// 2d. OAuth-only account password login
	oauthOnlyUser := &models.User{
		Username:        "oauth_only_login_user",
		Email:           "oauth_only_login@example.com",
		Password:        "",
		IsEmailVerified: true,
		IsActive:        true,
	}
	_ = userRepo.Create(ctx, oauthOnlyUser)
	if _, _, _, err := svc.Login(ctx, LoginInput{Email: oauthOnlyUser.Email, Password: "AnyPassword123!"}, "1.1.1.1", "GoTest"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for OAuth-only account, got %v", err)
	}

	// 3. ResendVerifyEmail layers
	// Layer 4: disposable domain -> returns nil
	if err := svc.ResendVerifyEmail(ctx, "disposable@mailinator.com", "1.1.1.1"); err != nil {
		t.Fatalf("expected nil for disposable domain, got %v", err)
	}
	// Layer 6: unknown email -> returns nil
	if err := svc.ResendVerifyEmail(ctx, "nonexistent_resend@example.com", "1.1.1.1"); err != nil {
		t.Fatalf("expected nil for unknown email, got %v", err)
	}
	// Layer 6: already verified -> returns nil
	if err := svc.ResendVerifyEmail(ctx, u1.Email, "1.1.1.1"); err != nil {
		t.Fatalf("expected nil for already verified user, got %v", err)
	}
	// Layer 6: valid unverified user -> succeeds!
	if err := svc.ResendVerifyEmail(ctx, unverifiedUser.Email, "1.1.1.1"); err != nil {
		t.Fatalf("ResendVerifyEmail failed: %v", err)
	}
	// Layer 5: per-email cap (max 2)
	_ = svc.ResendVerifyEmail(ctx, unverifiedUser.Email, "1.1.1.1")
	if err := svc.ResendVerifyEmail(ctx, unverifiedUser.Email, "1.1.1.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited for per-email cap, got %v", err)
	}

	// 4. ResetPassword edge cases
	resetTok, _ := jwtMgr.Issue(u1.ID, u1.Role, u1.Email, jwt.TokenTypeReset, time.Hour)
	// Weak password
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTok, NewPassword: "weak"}, "1.1.1.1"); err == nil {
		t.Fatal("expected error on weak new password")
	}

	// 5. ChangePassword edge cases
	// Missing user
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: 99999, OldPassword: "old", NewPassword: "NewPassword123!"}, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Wrong old password
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: unverifiedUser.ID, OldPassword: "WrongPassword!", NewPassword: "NewPassword123!"}, "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// Weak new password
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: unverifiedUser.ID, OldPassword: "Password123!", NewPassword: "weak"}, "1.1.1.1"); err == nil {
		t.Fatal("expected error on weak password")
	}
	// Valid password change
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: unverifiedUser.ID, OldPassword: "Password123!", NewPassword: "BrandNewSecurePassword123!"}, "1.1.1.1"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// 6. CompleteMFALogin with inactive user
	totpVal.err = nil
	if _, _, err := svc.CompleteMFALogin(ctx, CompleteMFALoginInput{UserID: inactiveUser.ID, Code: "123456"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for inactive user, got %v", err)
	}

	// 7. TOTP Service Enable and VerifyEnable branches
	enc := testEncryptor(t)
	totpSvc := NewTOTPService(totpRepo, memStore, auditRepo, "Issuer", config.AuthConfig{}, enc, jwtMgr, WithTOTPUserRepo(userRepo))
	// Enable first time
	sec, url, err := totpSvc.Enable(ctx, unverifiedUser.ID, unverifiedUser.Email, "")
	if err != nil || sec == "" || url == "" {
		t.Fatalf("Enable first time failed: sec=%s, url=%s, err=%v", sec, url, err)
	}
	// Abandoned enrollment re-enable (not yet verified/enabled)
	sec2, _, err := totpSvc.Enable(ctx, unverifiedUser.ID, unverifiedUser.Email, "")
	if err != nil || sec2 == "" {
		t.Fatalf("Enable on abandoned device failed: %v", err)
	}
	// VerifyEnable with wrong code
	if _, err := totpSvc.VerifyEnable(ctx, unverifiedUser.ID, "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}

	// 8. AdminService NDJSON export and User Locking
	adminSvc := NewAdminService(userRepo, sessionRepo, tokenRepo, auditRepo, memStore)
	// Lock self -> ErrCannotLockSelf
	if err := adminSvc.LockUser(ctx, 10, 10, time.Hour, "1.1.1.1"); !errors.Is(err, ErrCannotLockSelf) {
		t.Fatalf("expected ErrCannotLockSelf, got %v", err)
	}
	// Lock missing user -> ErrUserNotFound
	if err := adminSvc.LockUser(ctx, 10, 99999, time.Hour, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Lock with lockDuration <= 0
	if err := adminSvc.LockUser(ctx, 10, unverifiedUser.ID, 0, "1.1.1.1"); err != nil {
		t.Fatalf("LockUser with indefinite lock failed: %v", err)
	}
	// Unlock missing user -> ErrUserNotFound
	if err := adminSvc.UnlockUser(ctx, 10, 99999, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// ForceLogout missing user -> ErrUserNotFound
	if err := adminSvc.ForceLogout(ctx, 10, 99999, "1.1.1.1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// ExportAuditLogs NDJSON format
	rawNDJSON, mime, err := adminSvc.ExportAuditLogs(ctx, "ndjson")
	if err != nil || mime != "application/x-ndjson" || len(rawNDJSON) == 0 {
		t.Fatalf("ExportAuditLogs NDJSON failed: mime=%s, len=%d, err=%v", mime, len(rawNDJSON), err)
	}
}

func TestServices_Final_PushTo90(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.Session{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
		&models.PasskeyCredential{},
		&models.OAuthIdentity{},
		&models.WebhookEndpoint{},
		&models.WebhookDelivery{},
	)

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	sessionRepo := repositories.NewSessionRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	webhookRepo := repositories.NewWebhookRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")

	// Mock breached password server
	srvBreached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0018A:2\r\n"))
	}))
	defer srvBreached.Close()
	breachedChecker := NewBreachedPasswordChecker(srvBreached.URL+"/", time.Second)

	authCfg := config.AuthConfig{
		MaxLoginAttempts:     2,
		RequireEmailVerified: false,
		BcryptCost:           hash.MinCost,
	}
	rlCfg := config.RateLimitConfig{
		RegisterPerIPMax:         10,
		RegisterWindow:           time.Minute,
		VerifyResendGlobalMax:    1,
		VerifyResendGlobalWindow: time.Minute,
		VerifyResendPerIPMax:     1,
		VerifyResendPerIPWindow:  time.Minute,
		VerifyResendPerEmailMax:  1,
		VerifyResendWindow:       time.Minute,
	}
	jwtCfg := config.JWTConfig{
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
		VerifyTTL:  time.Hour,
		ResetTTL:   time.Hour,
	}
	notify := &mockNotifier{}

	svc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithSessionRepo(sessionRepo),
		WithAuthPasskeys(passkeyRepo),
		WithAuthOAuthIdents(oauthRepo),
		WithBreachedPasswordChecker(breachedChecker),
	)

	u := &models.User{
		Username:        "finalpushuser",
		Email:           "finalpush@example.com",
		Password:        "hashed",
		IsEmailVerified: true,
		IsActive:        true,
	}
	h, _ := hash.HashPassword("Password123!", hash.MinCost)
	u.Password = h
	_ = userRepo.Create(ctx, u)

	// 1. denylistSession edge cases
	svc.denylistSession(nil)
	svc.denylistSession(&models.Session{ID: ""})

	// 2. CurrentPwdVersion cache hit
	memStore.Set(fmt.Sprintf("pwdver:%d", u.ID), "42", time.Hour)
	if ver, err := svc.CurrentPwdVersion(ctx, u.ID); err != nil || ver != 42 {
		t.Fatalf("CurrentPwdVersion cache hit failed: ver=%d, err=%v", ver, err)
	}

	// 3. ListSessions legacy fallback (sessions == nil)
	svcLegacy := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	// #nosec G101 -- test mock token hash, not real credentials
	_ = tokenRepo.Create(ctx, &models.RefreshToken{
		TokenHash: "tok-sess-list-1",
		UserID:    u.ID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
		IPAddress: "1.2.3.4",
	})
	sessions, err := svcLegacy.ListSessions(ctx, u.ID, "")
	if err != nil || len(sessions) == 0 {
		t.Fatalf("ListSessions legacy fallback failed: len=%d, err=%v", len(sessions), err)
	}

	// 4. recordFailedLogin lockout trigger
	svc.recordFailedLogin(ctx, u, u.Email, "1.1.1.1")
	svc.recordFailedLogin(ctx, u, u.Email, "1.1.1.1")
	reloaded, _ := userRepo.FindByID(ctx, u.ID)
	if reloaded.LockedUntil == nil {
		t.Fatal("expected user to be locked after reaching MaxLoginAttempts")
	}

	// 5. RequestChangeEmail rate limits
	inReq := ChangeEmailRequestInput{
		Password: "Password123!",
		NewEmail: "fresh_unique_email@example.com",
	}
	// Call 1 succeeds
	if err := svc.RequestChangeEmail(ctx, u.ID, inReq, "1.1.1.1"); err != nil {
		t.Fatalf("RequestChangeEmail failed: %v", err)
	}
	// Call 2 trips rate limit (ChangeEmailGlobalMax / PerUserMax = 1)
	if err := svc.RequestChangeEmail(ctx, u.ID, inReq, "1.1.1.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited on repeated email change, got %v", err)
	}

	// 6. VerifyEmail already verified -> returns nil
	vTok, _ := jwtMgr.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeEmailVerify, time.Hour)
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: vTok}); err != nil {
		t.Fatalf("VerifyEmail for already verified user should return nil, got %v", err)
	}

	// 7. ForgotPassword & ResendVerifyEmail notify errors
	notify.verifySendErr = errors.New("smtp down")
	uUnverified := &models.User{
		Username: "unverified_final",
		Email:    "unverified_final@example.com",
		Password: h,
		IsActive: true,
	}
	_ = userRepo.Create(ctx, uUnverified)
	db.Model(uUnverified).Update("is_email_verified", false)
	if err := svc.ResendVerifyEmail(ctx, uUnverified.Email, "1.1.1.1"); err == nil {
		t.Fatal("expected error on notifier failure in ResendVerifyEmail")
	}
	notify.verifySendErr = nil

	// 8. OAuthService edge cases
	issuer := &mockTokenIssuer{pair: TokenPair{AccessToken: "acc", RefreshToken: "ref"}}
	verifier := &mockGoogleIDTokenVerifier{}
	client := &mockGoogleOAuthClient{
		authURL: "https://auth",
		token:   exchangeToken("id-tok"),
	}
	oauthSvc := NewOAuthService(userRepo, oauthRepo, memStore, issuer, verifier, client)

	// ConsumeState where stored value is not string (e.g. int)
	memStore.Set(oauthChallengeKey("int-state"), 12345, time.Minute)
	if _, err := oauthSvc.ConsumeState(ctx, "int-state"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid for non-string state, got %v", err)
	}

	// HandleCallback where token Extra("id_token") is missing
	clientNoIDTok := &mockGoogleOAuthClient{
		authURL: "https://auth",
		token:   &oauth2.Token{},
	}
	oauthSvcNoID := NewOAuthService(userRepo, oauthRepo, memStore, issuer, verifier, clientNoIDTok)
	memStore.Set(oauthChallengeKey("st-no-id"), `{"verifier":"v","nonce":"n"}`, time.Minute)
	if _, _, _, err := oauthSvcNoID.HandleCallback(ctx, "code", "st-no-id", "1.1.1.1", "GoTest"); !errors.Is(err, ErrOAuthTokenVerificationFailed) {
		t.Fatalf("expected ErrOAuthTokenVerificationFailed for missing id_token, got %v", err)
	}

	// findOrCreateUser with dangling link (identity exists, but user deleted)
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         88888,
		Provider:       "google",
		ProviderUserID: "dangling-sub",
	})
	memStore.Set(oauthChallengeKey("st-dangling"), `{"verifier":"v","nonce":"n"}`, time.Minute)
	verifier.claims = &GoogleIDTokenClaims{
		Sub:           "dangling-sub",
		Email:         "dangling@example.com",
		EmailVerified: true,
		Nonce:         "n",
	}
	if _, _, _, err := oauthSvc.HandleCallback(ctx, "code", "st-dangling", "1.1.1.1", "GoTest"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound for dangling identity, got %v", err)
	}

	// createGoogleUser username collision triggers random suffix
	_ = userRepo.Create(ctx, &models.User{
		Username:        "googlecollide",
		Email:           "other@example.com",
		IsEmailVerified: true,
	})
	memStore.Set(oauthChallengeKey("st-collide"), `{"verifier":"v","nonce":"n"}`, time.Minute)
	verifier.claims = &GoogleIDTokenClaims{
		Sub:           "sub-collide",
		Email:         "googlecollide@example.com",
		EmailVerified: true,
		Nonce:         "n",
	}
	pColl, _, _, err := oauthSvc.HandleCallback(ctx, "code", "st-collide", "1.1.1.1", "GoTest")
	if err != nil || pColl.AccessToken == "" {
		t.Fatalf("HandleCallback with username collision failed: %v", err)
	}

	// 9. PasskeyService edge cases
	pkSvc, err := NewPasskeyService(passkeyRepo, userRepo, auditRepo, memStore, &fakePasskeyIssuer{}, PasskeyConfig{
		RPDisplayName: "RP", RPID: "localhost", RPOrigins: []string{"http://localhost:8080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// FinishRegistration missing challenge
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/passkey/register", nil)
	if _, err := pkSvc.FinishRegistration(ctx, u.ID, req); !errors.Is(err, ErrPasskeyChallenge) {
		t.Fatalf("expected ErrPasskeyChallenge for FinishRegistration, got %v", err)
	}

	// 10. WebhookService edge cases
	webhookSvc := NewWebhookService(webhookRepo)
	// EnqueueEvent when repo is nil
	webhookSvcNil := &WebhookService{}
	if err := webhookSvcNil.EnqueueEvent(ctx, "t1", "ev", nil); err != nil {
		t.Fatalf("expected nil for EnqueueEvent with nil repo, got %v", err)
	}
	// DeliverOne when connection fails and Attempts == 4 (advances to 5 -> failed)
	dFail := &models.WebhookDelivery{
		ID:         "del-fail-final",
		EndpointID: "ep-1",
		Event:      "ev",
		Payload:    `{}`,
		Attempts:   4,
	}
	_ = webhookRepo.CreateDelivery(ctx, dFail)
	webhookSvc.SetAllowLocalhost(true)
	if err := webhookSvc.DeliverOne(ctx, dFail, "secret", "http://127.0.0.1:54321/unreachable"); err == nil {
		t.Fatal("expected error on unreachable webhook dial")
	}
}
