package services

// OAuth service unit tests. All external interactions (Google code exchange,
// ID token verification, token issuance) are mocked — no real network calls.
// The MFA-enforcement reuse is additionally proven end-to-end in
// TestOAuthCallbackRealMFAEnforcement by wiring the REAL AuthService (with a
// mock TOTP repo) as the TokenIssuer.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
// the given claims, and returns a freshly staged (valid) state. The mock
// verifier echoes the NONCE that BeginLogin staged for that state — the
// production binding the ID-token check enforces.
func (e *oauthTestEnv) primeCallback(t *testing.T, claims *GoogleIDTokenClaims) string {
	t.Helper()
	e.client.token = exchangeToken("fake-id-token")
	state, _, err := e.svc.BeginLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claims.Nonce = stagedNonce(t, e.store, state)
	e.verifier.claims = claims
	return state
}

// stagedNonce reads the staged challenge's nonce for a state (test mirror of
// the store contract).
func stagedNonce(t *testing.T, st *mockStore, state string) string {
	t.Helper()
	rawAny, ok := st.Get(oauthChallengeKey(state))
	if !ok {
		t.Fatal("challenge not staged for state")
	}
	var ch oauthChallenge
	if err := json.Unmarshal([]byte(rawAny.(string)), &ch); err != nil {
		t.Fatal(err)
	}
	return ch.Nonce
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

func TestOAuthChallengeLifecycle(t *testing.T) {
	env := newOAuthTestEnv()
	env.client.authURL = "https://accounts.google.com/o/oauth2/v2/auth"
	ctx := context.Background()

	s1, url1, err := env.svc.BeginLogin(ctx)
	if err != nil || len(s1) != 64 { // 32 bytes hex
		t.Fatalf("BeginLogin state=%q err=%v", s1, err)
	}
	// The consent URL must carry the state AND the S256 PKCE challenge.
	if !strings.Contains(url1, "state="+s1) || !strings.Contains(url1, "code_challenge_method=S256") {
		t.Fatalf("consent URL missing state/PKCE method: %q", url1)
	}
	s2, _, _ := env.svc.BeginLogin(ctx)
	if s1 == s2 {
		t.Fatal("states must be unique per generation")
	}

	// Consume: returns the staged challenge (verifier + nonce) and deletes it.
	ch, err := env.svc.ConsumeState(ctx, s1)
	if err != nil || ch.Verifier == "" || ch.Nonce == "" {
		t.Fatalf("ConsumeState=%+v err=%v", ch, err)
	}
	sum := sha256.Sum256([]byte(ch.Verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !strings.Contains(url1, "code_challenge="+wantChallenge) {
		t.Fatalf("URL challenge != S256(verifier): %q vs %q", url1, wantChallenge)
	}
	// One-time use: replay must fail.
	if _, err := env.svc.ConsumeState(ctx, s1); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("replayed state: err=%v", err)
	}
	// Unknown state rejected.
	if _, err := env.svc.ConsumeState(ctx, "bogus"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("unknown state: err=%v", err)
	}
	// Nil client (unconfigured) → empty URL so the handler can 501.
	unconfigured := NewOAuthService(newMockUserRepo(), newMockOAuthIdentityRepo(), newMockStore(), nil, nil, nil)
	if _, url, _ := unconfigured.BeginLogin(ctx); url != "" {
		t.Fatalf("unconfigured BeginLogin URL=%q, want empty", url)
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

func TestOAuthCallbackLinksExistingVerifiedUser(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()

	// Pre-register a password user with the same (verified-claims) email whose
	// local email was ALREADY verified — the only shape the link accepts.
	pwHash, err := hash.HashPassword("Password123", hash.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	existing := &models.User{
		Username: "bob", Email: "bob@example.com", Password: pwHash,
		FullName: "Bob Original", Role: models.RoleUser, IsActive: true,
		IsEmailVerified: true,
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

// TestOAuthCallbackUnverifiedEmailConflict pins the anti-takeover guard: a
// Google identity matching an existing local account whose email was NEVER
// verified must be REFUSED — no silent link, no flag promotion, no tokens.
// (Whoever controls the address could otherwise inherit the local account.)
func TestOAuthCallbackUnverifiedEmailConflict(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()

	existing := &models.User{
		Username: "carol", Email: "carol@example.com", Password: "hash",
		Role: models.RoleUser, IsActive: true, IsEmailVerified: false,
	}
	if err := env.users.Create(ctx, existing); err != nil {
		t.Fatal(err)
	}

	state := env.primeCallback(t, googleClaims("carol@example.com", true))
	_, _, _, err := env.svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA")
	if !errors.Is(err, ErrOAuthEmailTaken) {
		t.Fatalf("err=%v, want ErrOAuthEmailTaken", err)
	}
	// The local account is untouched: not linked, not verified-promoted,
	// no tokens issued.
	if n := env.idents.count(); n != 0 {
		t.Fatalf("identity linked for an unverified local account (n=%d)", n)
	}
	got, _ := env.users.FindByEmail(ctx, "carol@example.com")
	if got.IsEmailVerified {
		t.Fatal("email-verified flag must not be promoted by a refused link")
	}
	if len(env.issuer.users) != 0 {
		t.Fatal("tokens must not be issued for a refused link")
	}
}

// TestOAuthCallbackResolvesByIdentityRow pins the "sub is the source of
// truth" rule: once linked, the login resolves through oauth_identities —
// a DIFFERENT email on the Google identity cannot fork or hijack the login.
func TestOAuthCallbackResolvesByIdentityRow(t *testing.T) {
	env := newOAuthTestEnv()
	ctx := context.Background()

	pwHash, err := hash.HashPassword("Password123", hash.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	existing := &models.User{
		Username: "dave", Email: "dave@example.com", Password: pwHash,
		Role: models.RoleUser, IsActive: true, IsEmailVerified: true,
	}
	if err := env.users.Create(ctx, existing); err != nil {
		t.Fatal(err)
	}
	// First sign-in links sub=google-sub-123 → dave.
	state := env.primeCallback(t, googleClaims("dave@example.com", true))
	env.issuer.pair = TokenPair{AccessToken: "at", RefreshToken: "rt"}
	if _, _, _, err := env.svc.HandleCallback(ctx, "code", state, "1.2.3.4", "UA"); err != nil {
		t.Fatal(err)
	}
	// The user then changes their email AT GOOGLE — same sub, new email.
	env.issuer.pair = TokenPair{AccessToken: "at2", RefreshToken: "rt2"}
	claims := googleClaims("dave-new@example.com", true)
	state2 := env.primeCallback(t, claims)
	pair, _, pending, err := env.svc.HandleCallback(ctx, "code2", state2, "1.2.3.4", "UA")
	if err != nil {
		t.Fatalf("identity-row resolution must survive a Google-side email change: %v", err)
	}
	if pair.AccessToken != "at2" {
		t.Fatalf("expected the second pair, got %+v", pair)
	}
	if pending != nil {
		t.Fatalf("unexpected mfa pending: %+v", pending)
	}
	// The issuer must have been handed the LINKED user (resolved via the
	// identity row), not a fresh lookup by the changed email.
	if len(env.issuer.users) != 2 || env.issuer.users[1].ID != existing.ID {
		t.Fatalf("issuer users=%+v — login did not resolve to the linked user", env.issuer.users)
	}
	if len(env.users.users) != 1 {
		t.Fatalf("email change at the provider forked a new user (n=%d)", len(env.users.users))
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
		Role: models.RoleUser, IsActive: false, IsEmailVerified: true,
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
	state, _, _ := env.svc.BeginLogin(context.Background())

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

	pwHash, err := hash.HashPassword("Password123", hash.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	existing := &models.User{
		Username: "mfauser", Email: "mfa@example.com", Password: pwHash,
		Role: models.RoleUser, IsActive: true, IsEmailVerified: true,
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
		config.AuthConfig{MaxLoginAttempts: 5, LoginLockoutDuration: 15 * time.Minute, BcryptCost: hash.MinCost},
		config.RateLimitConfig{RPS: 100, Burst: 20, LoginPerAccountMax: 100},
		config.JWTConfig{AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, MFAPendingTTL: 5 * time.Minute},
		&mockNotifier{}, nil, nil, totpRepo, nil,
	)

	verifier := &mockGoogleIDTokenVerifier{}
	client := &mockGoogleOAuthClient{token: exchangeToken("id-token")}
	svc := NewOAuthService(users, idents, kvStore, authSvc, verifier, client)

	state, _, err := svc.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Echo the staged nonce so the ID-token binding passes (the point of this
	// test is the MFA enforcement, not the nonce).
	claims := googleClaims("mfa@example.com", true)
	claims.Nonce = stagedNonce(t, kvStore, state)
	verifier.claims = claims
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
	mfaClaims, err := jwtMgr.Verify(pending.MFAToken)
	if err != nil {
		t.Fatal(err)
	}
	if mfaClaims.Type != jwt.TokenTypeMFAPending {
		t.Fatalf("token type=%q, want %q", mfaClaims.Type, jwt.TokenTypeMFAPending)
	}
	if mfaClaims.UserID != existing.ID {
		t.Fatalf("token uid=%d, want %d", mfaClaims.UserID, existing.ID)
	}
}

func TestOAuthService_Unlink_SafetyAndAlert_P16(t *testing.T) {
	users := newMockUserRepo()
	idents := newMockOAuthIdentityRepo()
	notify := &mockNotifier{}
	audits := &mockAuditRepo{}

	// 1. Account with NO password and NO passkey cannot unlink (prevent account lock-out)
	u1 := &models.User{
		Email:           "googleonly@example.com",
		Username:        "googleonly",
		Password:        "", // No password
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = users.Create(context.Background(), u1)
	_ = idents.Create(context.Background(), &models.OAuthIdentity{
		UserID:         u1.ID,
		Provider:       "google",
		ProviderUserID: "sub-123",
	})

	svc := NewOAuthService(
		users, idents, newMockStore(), nil, nil, nil,
		WithOAuthNotifier(notify),
		WithOAuthAudits(audits),
	)

	err := svc.Unlink(context.Background(), u1.ID, "google", "127.0.0.1")
	if !errors.Is(err, ErrCannotUnlinkOnlyMethod) {
		t.Fatalf("expected ErrCannotUnlinkOnlyMethod when unlinking sole login method, got %v", err)
	}

	// 2. Account WITH password CAN unlink
	hashed, _ := hash.HashPassword("Password123", hash.MinCost)
	u1.Password = hashed
	_ = users.Update(context.Background(), u1)

	err = svc.Unlink(context.Background(), u1.ID, "google", "127.0.0.1")
	if err != nil {
		t.Fatalf("unlink failed: %v", err)
	}

	// Identity is removed
	existing, _ := idents.FindByUserIDAndProvider(context.Background(), u1.ID, "google")
	if existing != nil {
		t.Fatal("expected identity link removed")
	}
	if notify.alertCount() != 1 {
		t.Fatalf("expected security alert sent on unlink, got %d", notify.alertCount())
	}
}
