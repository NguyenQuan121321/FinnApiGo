// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
type GoogleOAuthClient interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
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

func (c *oauth2GoogleClient) AuthCodeURL(state string) string {
	return c.cfg.AuthCodeURL(state)
}

func (c *oauth2GoogleClient) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.cfg.Exchange(ctx, code)
}

// ---- Constants ----

const (
	// oauthProviderGoogle is the provider identifier stored in oauth_identities.
	oauthProviderGoogle = "google"

	// oauthStateTTL is how long an OAuth state token lives in the store.
	// 10 minutes gives the user ample time to authenticate with Google.
	oauthStateTTL = 10 * time.Minute

	// oauthStateBytes is the entropy of the CSRF state parameter.
	oauthStateBytes = 32 // 256 bits → 64 hex chars
)

// ---- OAuthService ----

// OAuthService implements the Google OAuth 2.0 / OpenID Connect sign-in flow:
// state generation/validation, code exchange, ID token verification, account
// linking, and delegation to TokenIssuer for MFA enforcement + token issuance.
// It never creates sessions directly — the shared CheckMFAOrIssueTokens path
// does, so OAuth and password logins behave identically downstream.
type OAuthService struct {
	users       UserRepo
	oauthIdents OAuthIdentityRepo
	store       store.Store
	issuer      TokenIssuer
	idVerifier  GoogleIDTokenVerifier
	client      GoogleOAuthClient // nil = feature disabled
}

// NewOAuthService constructs the OAuth service. All dependencies are
// interfaces so the service is trivially unit-testable. A nil client disables
// the flow at the callback stage (AuthorizationURL returns "").
func NewOAuthService(
	users UserRepo,
	oauthIdents OAuthIdentityRepo,
	store store.Store,
	issuer TokenIssuer,
	idVerifier GoogleIDTokenVerifier,
	client GoogleOAuthClient,
) *OAuthService {
	return &OAuthService{
		users: users, oauthIdents: oauthIdents, store: store,
		issuer: issuer, idVerifier: idVerifier, client: client,
	}
}

// GenerateState creates a cryptographically random state string and stores it
// in the store.Store with a 10-minute TTL. The caller must pass this state
// to AuthorizationURL and later to HandleCallback for validation.
func (s *OAuthService) GenerateState(ctx context.Context) (string, error) {
	b := make([]byte, oauthStateBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: generate state: %w", err)
	}
	state := hex.EncodeToString(b)
	if s.store != nil {
		key := "oauth:state:" + state
		if !s.store.SetNX(key, int64(1), oauthStateTTL) {
			// Extremely unlikely (256-bit collision), but handle it.
			return "", fmt.Errorf("oauth: state collision")
		}
	}
	return state, nil
}

// ValidateState checks that the state was previously generated and stored, and
// atomically consumes it (one-time use). The value is a counter: 1 = fresh,
// 2 = consumed. IncrBy is atomic on both the in-memory and Redis stores, so a
// concurrent replay of the same state gets n > 2 and is rejected.
func (s *OAuthService) ValidateState(ctx context.Context, state string) error {
	if s.store == nil || state == "" {
		return ErrOAuthStateInvalid
	}
	key := "oauth:state:" + state
	if _, ok := s.store.Get(key); !ok {
		return ErrOAuthStateInvalid
	}
	if n := s.store.IncrBy(key, 1, oauthStateTTL); n != 2 {
		return ErrOAuthStateInvalid // already consumed — replay
	}
	return nil
}

// AuthorizationURL builds the Google OAuth 2.0 consent-screen URL carrying the
// given CSRF state, with client_id / redirect_uri / scope (openid email
// profile) from configuration. Returns an empty string when Google OAuth is
// not configured.
func (s *OAuthService) AuthorizationURL(state string) string {
	if s.client == nil {
		return ""
	}
	return s.client.AuthCodeURL(state)
}

// HandleCallback processes the Google OAuth callback: validates the CSRF
// state, exchanges the authorization code for tokens, verifies the ID token
// (signature + audience via JWKS), enforces email_verified, links or creates
// the local user account, and delegates MFA enforcement + token issuance to
// the shared TokenIssuer — the exact same path as password Login.
func (s *OAuthService) HandleCallback(ctx context.Context, code, state, ip, ua string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	// ---- 1. Validate CSRF state BEFORE any network exchange ----
	if err := s.ValidateState(ctx, state); err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	if s.client == nil {
		return TokenPair{}, UserProfile{}, nil, ErrOAuthNotConfigured
	}

	// ---- 2. Exchange authorization code for tokens ----
	token, err := s.client.Exchange(ctx, code)
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

	// ---- 4. Enforce email_verified — never link an unverified email ----
	if !claims.EmailVerified {
		return TokenPair{}, UserProfile{}, nil, ErrOAuthEmailNotVerified
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))

	// ---- 5. Account linking (create or attach, never duplicate) ----
	user, err := s.findOrCreateUser(ctx, claims, email)
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

// findOrCreateUser looks up a user by verified email. If none exists it
// auto-registers one (IsEmailVerified=true — Google already proved control of
// the inbox, so the existing flag is reused rather than adding a second one).
// Either way it ensures an OAuthIdentity link exists for this Google account.
func (s *OAuthService) findOrCreateUser(ctx context.Context, claims *GoogleIDTokenClaims, email string) (*models.User, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("oauth: find user: %w", err)
	}

	if user == nil {
		user, err = s.createGoogleUser(ctx, claims, email)
		if err != nil {
			return nil, err
		}
	} else if !user.IsEmailVerified {
		// Existing password-registered account: Google's verification is
		// sufficient proof, so promote the flag on first Google sign-in.
		if err := s.users.SetEmailVerified(ctx, user, true); err != nil {
			return nil, fmt.Errorf("oauth: mark email verified: %w", err)
		}
		user.IsEmailVerified = true
	}

	if err := s.linkIdentity(ctx, user.ID, claims); err != nil {
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
func (s *OAuthService) linkIdentity(ctx context.Context, userID uint, claims *GoogleIDTokenClaims) error {
	existing, err := s.oauthIdents.FindByProviderAndProviderUserID(ctx, oauthProviderGoogle, claims.Sub)
	if err != nil {
		return fmt.Errorf("oauth: check identity: %w", err)
	}
	if existing != nil {
		return nil // already linked — nothing to do
	}
	identity := &models.OAuthIdentity{
		UserID:         userID,
		Provider:       oauthProviderGoogle,
		ProviderUserID: claims.Sub,
	}
	if err := s.oauthIdents.Create(ctx, identity); err != nil {
		return fmt.Errorf("oauth: link identity: %w", err)
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
