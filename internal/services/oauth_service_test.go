package services

// OAuth service unit tests. All external interactions (Google code exchange,
// ID token verification, token issuance) are mocked — no real network calls.
// The MFA-enforcement reuse is additionally proven end-to-end in
// TestOAuthCallbackRealMFAEnforcement by wiring the REAL AuthService (with a
// mock TOTP repo) as the TokenIssuer.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
)

// oauthTestEnv bundles the service plus every mock so tests can inspect state.
type oauthTestEnv struct {
	svc      *OAuthService
	users    *mockUserRepo
	idents   *mockOAuthIdentityRepo
	store    *mockStore
	verifier *mockGoogleIDTokenVerifier
	client   *mockGoogleOAuthClient
	issuer   *mockTokenIssuer
}

func newOAuthTestEnv() *oauthTestEnv {
	env := &oauthTestEnv{
		users:    newMockUserRepo(),
		idents:   newMockOAuthIdentityRepo(),
		store:    newMockStore(),
		verifier: &mockGoogleIDTokenVerifier{},
		client:   &mockGoogleOAuthClient{},
		issuer:   &mockTokenIssuer{},
	}
	env.svc = NewOAuthService(env.users, env.idents, env.store, env.issuer, env.verifier, env.client)
	return env
}

// primeCallback wires the mocks for a successful exchange+verification using
// the given claims, and returns a freshly generated (valid) state.
func (e *oauthTestEnv) primeCallback(t *testing.T, claims *GoogleIDTokenClaims) string {
	t.Helper()
	e.verifier.claims = claims
	e.client.token = exchangeToken("fake-id-token")
	state, err := e.svc.GenerateState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// exchangeToken builds an oauth2.Token shaped like Google's token endpoint
// response (access/refresh + id_token in the extra fields).
func exchangeToken(idToken string) *oauth2.Token {
	tk := &oauth2.Token{
		AccessToken:  "g-access",
		TokenType:    "Bearer",
		RefreshToken: "g-refresh",
		Expiry:       time.Now().Add(time.Hour),
	}
	return tk.WithExtra(map[string]interface{}{"id_token": idToken})
}

func googleClaims(email string, verified bool) *GoogleIDTokenClaims {
	return &GoogleIDTokenClaims{
		Sub:           "google-sub-123",
		Email:         email,
		EmailVerified: verified,
		Name:          "Google User",
		Picture:       "https://lh3.googleusercontent.com/u/0/photo.jpg",
	}
}

func TestOAuthGenerateAndValidateState(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()

	s1, err := env.svc.GenerateState(ctx)
	if err != nil || len(s1) != 64 { // 32 bytes hex
		t.Fatalf("GenerateState=%q err=%v", s1, err)
	}
	s2, _ := env.svc.GenerateState(ctx)
	if s1 == s2 {
		t.Fatal("states must be unique per generation")
	}
	if err := env.svc.ValidateState(ctx, s1); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	// One-time use: replay must fail.
	if err := env.svc.ValidateState(ctx, s1); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("replayed state: err=%v", err)
	}
	// Unknown state rejected.
	if err := env.svc.ValidateState(ctx, "bogus"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("unknown state: err=%v", err)
	}
}

func TestOAuthAuthorizationURL(t *testing.T) {
	env := newOAuthTestEnv()
	env.client.authURL = "https://accounts.google.com/o/oauth2/v2/auth"
	url := env.svc.AuthorizationURL("abc123")
	if !strings.Contains(url, "state=abc123") {
		t.Fatalf("URL missing state: %q", url)
	}
	// Nil client (unconfigured) → empty URL so the handler can 501.
	unconfigured := NewOAuthService(newMockUserRepo(), newMockOAuthIdentityRepo(), newMockStore(), nil, nil, nil)
	if got := unconfigured.AuthorizationURL("x"); got != "" {
		t.Fatalf("unconfigured AuthorizationURL=%q, want empty", got)
	}
}

func TestOAuthCallbackNewUser(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()
	state := env.primeCallback(t, googleClaims("New.User@Example.com", true))
	env.issuer.pair = TokenPair{AccessToken: "at", RefreshToken: "rt"}
	env.issuer.profile = UserProfile{ID: 1, Email: "new.user@example.com"}

	pair, profile, pending, err := env.svc.HandleCallback(ctx, "auth-code", state, "1.2.3.4", "UA")
	if err != nil {
		t.Fatal(err)
	}
	if pending != nil {
		t.Fatalf("expected full tokens, got mfa pending: %+v", pending)
	}
	if pair.AccessToken != "at" || profile.Email != "new.user@example.com" {
		t.Fatalf("issuer passthrough wrong: %+v %+v", pair, profile)
	}

	// User auto-registered with verified email + linked identity.
	if len(env.users.users) != 1 {
		t.Fatalf("expected exactly 1 user, got %d", len(env.users.users))
	}
	created := env.users.users[1]
	if !created.IsEmailVerified || !created.IsActive || created.Email != "new.user@example.com" {
		t.Fatalf("unexpected created user: %+v", created)
	}
	if created.Username != "new.user" { // derived from email local-part
		t.Fatalf("username=%q", created.Username)
	}
	if n := env.idents.count(); n != 1 {
		t.Fatalf("expected 1 identity link, got %d", n)
	}
	link, _ := env.idents.FindByProviderAndProviderUserID(ctx, "google", "google-sub-123")
	if link == nil || link.UserID != created.ID {
		t.Fatalf("identity not linked: %+v", link)
	}
	// Issuer saw the right user + audit detail.
	if len(env.issuer.users) != 1 || env.issuer.users[0].ID != created.ID {
		t.Fatal("issuer did not receive the created user")
	}
	if d := env.issuer.details[0]; d != "google-oauth" {
		t.Fatalf("audit detail=%q, want google-oauth", d)
	}
}

func TestOAuthCallbackLinksExistingPasswordUser(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()

	// Pre-register a password user with the same (verified-claims) email.
	pwHash, err := hash.HashPassword("Password123")
	if err != nil {
		t.Fatal(err)
	}
	existing := &models.User{
		Username: "bob", Email: "bob@example.com", Password: pwHash,
		FullName: "Bob Original", Role: models.RoleUser, IsActive: true,
	}
	if err := env.users.Create(ctx, existing); err != nil {
		t.Fatal(err)
	}

	state := env.primeCallback(t, googleClaims("bob@example.com", true))
	env.issuer.pair = TokenPair{AccessToken: "at", RefreshToken: "rt"}
	pair, _, pending, err := env.svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA")
	if err != nil {
		t.Fatal(err)
	}
	if pending != nil || pair.AccessToken == "" {
		t.Fatalf("expected full tokens: pair=%+v pending=%+v", pair, pending)
	}

	// No duplicate user row; the existing record was reused.
	if len(env.users.users) != 1 {
		t.Fatalf("expected 1 user total, got %d — duplicate created?", len(env.users.users))
	}
	got, _ := env.users.FindByEmail(ctx, "bob@example.com")
	if got.ID != existing.ID {
		t.Fatalf("linked to wrong user: %d vs %d", got.ID, existing.ID)
	}
	// Google's verification promotes the email-verified flag on first sign-in.
	if !got.IsEmailVerified {
		t.Fatal("existing user's IsEmailVerified should be promoted to true")
	}
	// Password untouched — the user can still log in via password.
	if got.Password != pwHash {
		t.Fatal("existing user's password hash must not change")
	}
	// Identity linked to the existing user.
	link, _ := env.idents.FindByProviderAndProviderUserID(ctx, "google", "google-sub-123")
	if link == nil || link.UserID != existing.ID {
		t.Fatalf("identity not linked to existing user: %+v", link)
	}
	// Second sign-in must not create another identity row (idempotent link).
	state2 := env.primeCallback(t, googleClaims("bob@example.com", true))
	if _, _, _, err := env.svc.HandleCallback(ctx, "code2", state2, "1.2.3.4", "UA"); err != nil {
		t.Fatal(err)
	}
	if n := env.idents.count(); n != 1 {
		t.Fatalf("second sign-in created a duplicate identity link (n=%d)", n)
	}
}

func TestOAuthCallbackEmailNotVerifiedRejected(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()
	state := env.primeCallback(t, googleClaims("evil@example.com", false))

	_, _, _, err := env.svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA")
	if !errors.Is(err, ErrOAuthEmailNotVerified) {
		t.Fatalf("err=%v, want ErrOAuthEmailNotVerified", err)
	}
	// No user created, no link, no tokens issued.
	if len(env.users.users) != 0 || env.idents.count() != 0 || len(env.issuer.users) != 0 {
		t.Fatalf("unverified email must not create/link/issue: users=%d idents=%d issued=%d",
			len(env.users.users), env.idents.count(), len(env.issuer.users))
	}
}

func TestOAuthCallbackInvalidStateRejectedBeforeExchange(t *testing.T) {
	env := newOAuthTestEnv()
	env.verifier.claims = googleClaims("a@example.com", true)
	env.client.token = exchangeToken("tok")

	_, _, _, err := env.svc.HandleCallback(context.Background(), "code", "forged-state", "1.2.3.4", "UA")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("err=%v, want ErrOAuthStateInvalid", err)
	}
	// The code exchange must NEVER run for an invalid state.
	if len(env.client.codes) != 0 {
		t.Fatal("token exchange ran despite invalid state")
	}
	if len(env.verifier.tokens) != 0 {
		t.Fatal("id token verification ran despite invalid state")
	}
}

func TestOAuthCallbackStateReplayRejected(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()
	state := env.primeCallback(t, googleClaims("replay@example.com", true))

	if _, _, _, err := env.svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, _, _, err := env.svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("replay err=%v, want ErrOAuthStateInvalid", err)
	}
	if len(env.client.codes) != 1 {
		t.Fatalf("replay must not reach exchange (exchanges=%d)", len(env.client.codes))
	}
}

func TestOAuthCallbackDisabledUserRejected(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()

	disabled := &models.User{
		Username: "banned", Email: "banned@example.com", Password: "hash",
		Role: models.RoleUser, IsActive: false,
	}
	if err := env.users.Create(ctx, disabled); err != nil {
		t.Fatal(err)
	}
	state := env.primeCallback(t, googleClaims("banned@example.com", true))

	_, _, _, err := env.svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA")
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("err=%v, want ErrAccountDisabled", err)
	}
	if len(env.issuer.users) != 0 {
		t.Fatal("tokens must not be issued for a disabled account")
	}
}

func TestOAuthCallbackBadIDTokenRejected(t *testing.T) {
	env := newOAuthTestEnv()
	env.verifier.claims = googleClaims("a@example.com", true)
	env.verifier.err = ErrOAuthTokenVerificationFailed
	env.client.token = exchangeToken("tampered-token")
	state, _ := env.svc.GenerateState(context.Background())

	_, _, _, err := env.svc.HandleCallback(context.Background(), "code", state, "1.2.3.4", "UA")
	if !errors.Is(err, ErrOAuthTokenVerificationFailed) {
		t.Fatalf("err=%v, want ErrOAuthTokenVerificationFailed", err)
	}
	if len(env.users.users) != 0 {
		t.Fatal("no user may be created from an unverifiable token")
	}
}

// TestOAuthCallbackRealMFAEnforcement proves the OAuth path runs through the
// REAL AuthService MFA check: a user with an enabled TOTP device gets an
// mfa_pending JWT (type=mfa_pending), NOT full tokens — exactly like password
// login. This is the §3 requirement: MFA enforcement must not be weakened.
func TestOAuthCallbackRealMFAEnforcement(t *testing.T) {
	ctx := context.Background()
	users := newMockUserRepo()
	idents := newMockOAuthIdentityRepo()
	kvStore := newMockStore()

	pwHash, err := hash.HashPassword("Password123")
	if err != nil {
		t.Fatal(err)
	}
	existing := &models.User{
		Username: "mfauser", Email: "mfa@example.com", Password: pwHash,
		Role: models.RoleUser, IsActive: true,
	}
	if err := users.Create(ctx, existing); err != nil {
		t.Fatal(err)
	}
	totpRepo := newMockTOTPRepo()
	if err := totpRepo.Upsert(ctx, &models.TOTPDevice{UserID: existing.ID, Secret: "S", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	authSvc := NewAuthService(
		users, newMockTokenRepo(), newMockUsedTokenRepo(), &mockAuditRepo{}, kvStore,
		jwtMgr,
		config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: 15 * time.Minute},
		config.RateLimitConfig{RPS: 100, Burst: 20, LoginPerAccountMax: 100},
		config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, MFAPendingTTL: 5 * time.Minute},
		&mockNotifier{}, nil, nil, totpRepo, nil,
	)

	verifier := &mockGoogleIDTokenVerifier{claims: googleClaims("mfa@example.com", true)}
	client := &mockGoogleOAuthClient{token: exchangeToken("id-token")}
	svc := NewOAuthService(users, idents, kvStore, authSvc, verifier, client)

	state, err := svc.GenerateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pair, _, pending, err := svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA")
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil || !pending.MFARequired || pending.MFAToken == "" {
		t.Fatalf("expected mfa pending result, got %+v", pending)
	}
	if pair.AccessToken != "" || pair.RefreshToken != "" {
		t.Fatalf("full tokens must NOT be issued before MFA: %+v", pair)
	}
	// The pending token must be a genuine type=mfa_pending JWT — i.e. the
	// exact same token the password flow issues, completable via the
	// EXISTING /mfa/login-verify endpoint.
	claims, err := jwtMgr.Verify(pending.MFAToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Type != jwt.TokenTypeMFAPending {
		t.Fatalf("token type=%q, want %q", claims.Type, jwt.TokenTypeMFAPending)
	}
	if claims.UserID != existing.ID {
		t.Fatalf("token uid=%d, want %d", claims.UserID, existing.ID)
	}
}
