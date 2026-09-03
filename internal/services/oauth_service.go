// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/store"
)

// ---- Google OAuth types ----

// GoogleIDTokenClaims holds the verified claims extracted from a Google ID token.
// Only fields needed by the OAuth callback flow are included.
type GoogleIDTokenClaims struct {
	Sub           string // Google's stable user ID ("sub" — never recycled)
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Nonce         string // replay-binding claim echoed by Google (checked against the challenge)
}

// GoogleIDTokenVerifier abstracts Google ID token verification so the service
// layer can be tested without real network calls to Google's JWKS endpoint.
// The production implementation uses google.golang.org/api/idtoken.Validate,
// which fetches Google's JWKS and validates signature, expiry, and audience.
type GoogleIDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*GoogleIDTokenClaims, error)
}

// TokenIssuer abstracts the shared MFA-check + token-issuance logic so the
// OAuthService can reuse the exact same enforcement path as password Login
// without depending on the concrete AuthService.
type TokenIssuer interface {
	CheckMFAOrIssueTokens(ctx context.Context, user *models.User, ip, ua, auditDetail string) (TokenPair, UserProfile, *MFAPendingResult, error)
}

// GoogleOAuthClient abstracts the two Google OAuth HTTP interactions —
// building the consent-screen URL and exchanging the authorization code for
// tokens. Production wraps golang.org/x/oauth2 (standard, well-audited — no
// hand-rolled exchange); tests inject a fake so no real network calls happen.
// Both methods carry PKCE (RFC 7636): the S256 challenge rides on the consent
// URL, the verifier is handed to the exchange.
type GoogleOAuthClient interface {
	AuthCodeURL(state, codeChallenge, nonce string) string
	Exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error)
}

// oauth2GoogleClient is the production client backed by golang.org/x/oauth2.
type oauth2GoogleClient struct{ cfg *oauth2.Config }

// NewGoogleOAuthClient returns the production client, or nil when Google
// sign-in is not configured (empty client ID or redirect URL) — callers treat
// a nil client as "feature disabled".
func NewGoogleOAuthClient(clientID, clientSecret, redirectURL string) GoogleOAuthClient {
	if clientID == "" || redirectURL == "" {
		return nil
	}
	return &oauth2GoogleClient{cfg: &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}}
}

func (c *oauth2GoogleClient) AuthCodeURL(state, codeChallenge, nonce string) string {
	if nonce != "" {
		return c.cfg.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("nonce", nonce),
		)
	}
	return c.cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *oauth2GoogleClient) Exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return c.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
}

// ---- Constants ----

const (
	// oauthProviderGoogle is the provider identifier stored in oauth_identities.
	oauthProviderGoogle = "google"

	// oauthStateTTL is how long an OAuth challenge lives in the store.
	// 10 minutes gives the user ample time to authenticate with Google.
	oauthStateTTL = 10 * time.Minute

	// oauthStateBytes is the entropy of the CSRF state parameter.
	oauthStateBytes = 32 // 256 bits → 64 hex chars

	// oauthNonceBytes is the entropy of the ID-token nonce.
	oauthNonceBytes = 16 // 128 bits → 32 hex chars
)

// oauthChallenge is the server-side state stored (encrypted at rest only by
// the store backend's isolation — it holds nothing secret beyond a PKCE
// verifier, which is useless without the code) for one login attempt.
type oauthChallenge struct {
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
}

func oauthChallengeKey(state string) string { return "oauth:state:" + state }

// ---- OAuthService ----

// OAuthService implements the Google OAuth 2.0 / OpenID Connect sign-in flow:
// state generation/validation, PKCE, code exchange, ID token verification
// (signature + audience + nonce), account linking, and delegation to
// TokenIssuer for MFA enforcement + token issuance. It never creates sessions
// directly — the shared CheckMFAOrIssueTokens path does, so OAuth and
// password logins behave identically downstream.
type OAuthService struct {
	users       UserRepo
	oauthIdents OAuthIdentityRepo
	store       store.Store
	issuer      TokenIssuer
	idVerifier  GoogleIDTokenVerifier
	client      GoogleOAuthClient // nil = feature disabled
	notifier    Notifier
	audits      AuditRepo
	passkeys    PasskeyRepo
}

// OAuthOption configures optional dependencies on OAuthService.
type OAuthOption func(*OAuthService)

// WithOAuthNotifier wires Notifier for security alerts on link/unlink (P1.6).
func WithOAuthNotifier(n Notifier) OAuthOption {
	return func(s *OAuthService) { s.notifier = n }
}

// WithOAuthAudits wires AuditRepo for security event logging (P1.6).
func WithOAuthAudits(a AuditRepo) OAuthOption {
	return func(s *OAuthService) { s.audits = a }
}

// WithOAuthPasskeys wires PasskeyRepo for login method verification on unlink (P1.6).
func WithOAuthPasskeys(p PasskeyRepo) OAuthOption {
	return func(s *OAuthService) { s.passkeys = p }
}

// NewOAuthService constructs the OAuth service. All dependencies are
// interfaces so the service is trivially unit-testable. A nil client disables
// the flow (BeginLogin returns an empty URL).
func NewOAuthService(
	users UserRepo,
	oauthIdents OAuthIdentityRepo,
	store store.Store,
	issuer TokenIssuer,
	idVerifier GoogleIDTokenVerifier,
	client GoogleOAuthClient,
	opts ...OAuthOption,
) *OAuthService {
	s := &OAuthService{
		users: users, oauthIdents: oauthIdents, store: store,
		issuer: issuer, idVerifier: idVerifier, client: client,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// BeginLogin creates a full login attempt: a CSPRNG CSRF state, a PKCE S256
// verifier, and an ID-token nonce — all staged server-side under the state
// key with a 10-minute TTL. It returns the state (the handler ALSO binds it
// to the browser via an HttpOnly cookie, closing login CSRF) and the consent
// URL. An empty URL means Google sign-in is not configured.
func (s *OAuthService) BeginLogin(ctx context.Context) (state, redirectURL string, err error) {
	if s.client == nil {
		return "", "", nil
	}
	sb := make([]byte, oauthStateBytes)
	if _, err = rand.Read(sb); err != nil {
		return "", "", fmt.Errorf("oauth: generate state: %w", err)
	}
	state = hex.EncodeToString(sb)

	verifier, err := pkceVerifier()
	if err != nil {
		return "", "", err
	}
	nb := make([]byte, oauthNonceBytes)
	if _, err = rand.Read(nb); err != nil {
		return "", "", fmt.Errorf("oauth: generate nonce: %w", err)
	}
	challenge := oauthChallenge{Verifier: verifier, Nonce: hex.EncodeToString(nb)}

	if s.store != nil {
		raw, err := json.Marshal(challenge)
		if err != nil {
			return "", "", fmt.Errorf("oauth: marshal challenge: %w", err)
		}
		if !s.store.SetNX(oauthChallengeKey(state), string(raw), oauthStateTTL) {
			// Extremely unlikely (256-bit collision), but fail closed.
			return "", "", fmt.Errorf("oauth: state collision")
		}
	}
	return state, s.client.AuthCodeURL(state, s256Challenge(verifier), challenge.Nonce), nil
}

// ConsumeState atomically validates AND deletes the challenge for state —
// one-time use on every backend (Store.Take). The stored challenge (PKCE
// verifier + nonce) is returned for the exchange and the ID-token check.
func (s *OAuthService) ConsumeState(ctx context.Context, state string) (*oauthChallenge, error) {
	if s.store == nil || state == "" {
		// No store: nothing staged to validate — refuse rather than run an
		// unbound flow.
		return nil, ErrOAuthStateInvalid
	}
	rawAny, ok := s.store.Take(oauthChallengeKey(state))
	if !ok {
		return nil, ErrOAuthStateInvalid // missing, expired, or already consumed
	}
	raw, ok := rawAny.(string)
	if !ok {
		return nil, ErrOAuthStateInvalid
	}
	var challenge oauthChallenge
	if err := json.Unmarshal([]byte(raw), &challenge); err != nil || challenge.Verifier == "" {
		return nil, ErrOAuthStateInvalid
	}
	return &challenge, nil
}

// s256Challenge derives the PKCE code challenge (RFC 7636 section 4.2):
// BASE64URL-ENCODE(SHA256(ASCII(verifier))).
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pkceVerifier generates a fresh PKCE code verifier (S256): 64 CSPRNG bytes
// base64url-encoded — 86 chars, inside the RFC 7636 43..128 range, with the
// unreserved-character guarantee base64url provides.
func pkceVerifier() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: pkce verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HandleCallback processes the Google OAuth callback: consumes the CSRF
// state (atomic single-use), exchanges the authorization code WITH the PKCE
// verifier, verifies the ID token (JWKS signature + audience + nonce),
// enforces email_verified, links or creates the local user account, and
// delegates MFA enforcement + token issuance to the shared TokenIssuer — the
// exact same path as password Login.
func (s *OAuthService) HandleCallback(ctx context.Context, code, state, ip, ua string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	// ---- 1. Consume the CSRF state BEFORE any network exchange ----
	challenge, err := s.ConsumeState(ctx, state)
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	if s.client == nil {
		return TokenPair{}, UserProfile{}, nil, ErrOAuthNotConfigured
	}

	// ---- 2. Exchange the authorization code (PKCE verifier attached) ----
	token, err := s.client.Exchange(ctx, code, challenge.Verifier)
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, fmt.Errorf("%w: %w", ErrOAuthCodeExchangeFailed, err)
	}

	// ---- 3. Extract & verify the ID token (JWKS signature + audience) ----
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return TokenPair{}, UserProfile{}, nil, ErrOAuthTokenVerificationFailed
	}
	claims, err := s.idVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	// Nonce binding: the ID token must echo the nonce staged with THIS state,
	// so a stolen/borrowed code+token pair for a different attempt is useless.
	if claims.Nonce == "" || claims.Nonce != challenge.Nonce {
		return TokenPair{}, UserProfile{}, nil, ErrOAuthTokenVerificationFailed
	}

	// ---- 4. Enforce email_verified — never link an unverified email ----
	if !claims.EmailVerified {
		return TokenPair{}, UserProfile{}, nil, ErrOAuthEmailNotVerified
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))

	// ---- 5. Account linking (create or attach, never duplicate) ----
	user, err := s.findOrCreateUser(ctx, claims, email, ip)
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}

	// ---- 6. Account status ----
	if !user.IsActive {
		return TokenPair{}, UserProfile{}, nil, ErrAccountDisabled
	}

	// ---- 7. MFA check + token issuance (shared with password Login) ----
	return s.issuer.CheckMFAOrIssueTokens(ctx, user, ip, ua, "google-oauth")
}

// findOrCreateUser resolves the local account for a verified Google identity.
//
// Resolution order matters for security:
//  1. The persisted identity row (provider, sub) is the source of truth —
//     "sub" is Google's stable user ID, so a Google-side email CHANGE cannot
//     fork the login onto a different local account or bypass the link.
//  2. Without a link, an existing local user is attached ONLY when their
//     email was already verified. Auto-linking an UNVERIFIED local account on
//     an email match is the classic takeover pattern (whoever controls that
//     address after reassignment would inherit the account).
//  3. Otherwise a fresh account is provisioned from the verified identity.
func (s *OAuthService) findOrCreateUser(ctx context.Context, claims *GoogleIDTokenClaims, email, ip string) (*models.User, error) {
	// 1. The stored link wins.
	ident, err := s.oauthIdents.FindByProviderAndProviderUserID(ctx, oauthProviderGoogle, claims.Sub)
	if err != nil {
		return nil, fmt.Errorf("oauth: check identity: %w", err)
	}
	if ident != nil {
		user, err := s.users.FindByID(ctx, ident.UserID)
		if err != nil {
			return nil, fmt.Errorf("oauth: find linked user: %w", err)
		}
		if user == nil {
			// Dangling link (user row deleted without cleaning identities) —
			// refuse rather than silently re-provisioning under the same sub.
			return nil, ErrUserNotFound
		}
		return user, nil
	}

	// 2. Match by email — verified local accounts only.
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("oauth: find user: %w", err)
	}
	if user != nil {
		if !user.IsEmailVerified {
			// Unverified local account with this email: REFUSE. Google's
			// verification proves control of the address NOW, but it says
			// nothing about who registered the local account — the flag
			// promotion this branch used to do was the takeover vector.
			return nil, ErrOAuthEmailTaken
		}
	} else {
		// 3. Provision a new account from the verified identity.
		user, err = s.createGoogleUser(ctx, claims, email)
		if err != nil {
			return nil, err
		}
	}

	if err := s.linkIdentity(ctx, user, claims, ip); err != nil {
		return nil, err
	}
	return user, nil
}

// createGoogleUser auto-registers a user from a verified Google identity.
// The username derives from the email local-part; on collision a random hex
// suffix is appended. Password stays empty — the account cannot password-login
// until the user sets one (bcrypt comparison against "" always fails).
func (s *OAuthService) createGoogleUser(ctx context.Context, claims *GoogleIDTokenClaims, email string) (*models.User, error) {
	username := generateUsernameFromEmail(email)
	if existing, err := s.users.FindByUsername(ctx, username); err != nil {
		return nil, fmt.Errorf("oauth: check username: %w", err)
	} else if existing != nil {
		suffix, serr := randomSuffix()
		if serr != nil {
			return nil, serr
		}
		username += suffix
	}
	user := &models.User{
		Username:        username,
		Email:           email,
		Password:        "", // Google-only account until the user sets a password
		FullName:        claims.Name,
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
	}
	if err := s.users.Create(ctx, user); err != nil {
		// TOCTOU race on a concurrent register/sign-in: the DB unique index
		// rejects the insert — map it to the proper sentinel (§1.7).
		return nil, mapDuplicateKey(email, username, err)
	}
	return user, nil
}

// linkIdentity creates an oauth_identities row for this user + Google account.
// If the identity already exists (prior sign-in), this is a no-op.
// Sends notification email and records audit log (P1.6).
func (s *OAuthService) linkIdentity(ctx context.Context, user *models.User, claims *GoogleIDTokenClaims, ip string) error {
	existing, err := s.oauthIdents.FindByProviderAndProviderUserID(ctx, oauthProviderGoogle, claims.Sub)
	if err != nil {
		return fmt.Errorf("oauth: check identity: %w", err)
	}
	if existing != nil {
		return nil // already linked — nothing to do
	}
	identity := &models.OAuthIdentity{
		UserID:         user.ID,
		Provider:       oauthProviderGoogle,
		ProviderUserID: claims.Sub,
	}
	if err := s.oauthIdents.Create(ctx, identity); err != nil {
		return fmt.Errorf("oauth: link identity: %w", err)
	}
	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			UserID:    &user.ID,
			Email:     user.Email,
			Event:     models.AuditEventOAuthLinked,
			IPAddress: ip,
			Success:   true,
			Detail:    "linked google oauth account",
		})
	}
	if s.notifier != nil {
		_ = s.notifier.SendSecurityAlert(ctx, user.Email, "oauth_linked", "A Google account has been connected to your profile.")
	}
	return nil
}

// Unlink disconnects an OAuth provider from the user's account (P1.6).
// Refuses if this is the user's only login method without a usable password.
func (s *OAuthService) Unlink(ctx context.Context, userID uint, provider, ip string) error {
	existing, err := s.oauthIdents.FindByUserIDAndProvider(ctx, userID, provider)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrUserNotFound
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	hasPassword := user.Password != ""
	hasPasskey := false
	if s.passkeys != nil {
		pks, err := s.passkeys.ListByUser(ctx, userID, false)
		if err == nil && len(pks) > 0 {
			hasPasskey = true
		}
	}
	if !hasPassword && !hasPasskey {
		return ErrCannotUnlinkOnlyMethod
	}

	if err := s.oauthIdents.DeleteByUserIDAndProvider(ctx, userID, provider); err != nil {
		return err
	}

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			UserID:    &user.ID,
			Email:     user.Email,
			Event:     models.AuditEventOAuthUnlinked,
			IPAddress: ip,
			Success:   true,
			Detail:    fmt.Sprintf("unlinked %s oauth account", provider),
		})
	}
	if s.notifier != nil {
		_ = s.notifier.SendSecurityAlert(ctx, user.Email, "oauth_unlinked", fmt.Sprintf("Your %s account was disconnected from your profile.", provider))
	}
	return nil
}

// generateUsernameFromEmail derives a username from an email local-part.
// Uniqueness is enforced by lookup + DB unique index (see createGoogleUser).
func generateUsernameFromEmail(email string) string {
	at := strings.Index(email, "@")
	if at > 0 {
		return email[:at]
	}
	return email
}

// randomSuffix returns 6 hex chars of entropy for username collision retries.
func randomSuffix() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: random suffix: %w", err)
	}
	return hex.EncodeToString(b), nil
}
