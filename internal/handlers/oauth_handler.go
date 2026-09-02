package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// OAuthStateCookie binds the CSRF state to the browser: set (HttpOnly,
// SameSite=Lax) by /google/login, compared at /google/callback, then cleared.
// Without this binding, an attacker who mints their own valid state and
// obtains an authorization code for THEIR Google account could drop
// callback?code=ATTACKER&state=ATTACKER into a victim's browser (login CSRF —
// the victim silently signs into the attacker's session). The attacker cannot
// plant a cookie on OUR origin, so the double-submit check rejects it.
const OAuthStateCookie = "finnapigo_oauth_state"

// oauthStateCookieMaxAge matches the server-side challenge TTL (10 minutes).
const oauthStateCookieMaxAge = 600

// OAuthService is the handler-layer contract for the Google OAuth flow.
// Each method corresponds to one HTTP endpoint; the handler never touches
// the database or OAuth HTTP calls directly.
type OAuthService interface {
	// BeginLogin stages the server-side challenge (state + PKCE verifier +
	// nonce) and returns the state and the Google consent URL (empty when
	// OAuth is not configured).
	BeginLogin(ctx context.Context) (state, redirectURL string, err error)
	HandleCallback(ctx context.Context, code, state, ip, ua string) (services.TokenPair, services.UserProfile, *services.MFAPendingResult, error)
}

// OAuthHandler exposes GET /api/v1/auth/google/login and GET /api/v1/auth/google/callback.
type OAuthHandler struct {
	svc OAuthService
}

// NewOAuthHandler constructs the handler with the given service interface.
func NewOAuthHandler(svc OAuthService) *OAuthHandler {
	return &OAuthHandler{svc: svc}
}

// GoogleLogin godoc
//
//	@Summary      Start the Google OAuth flow
//	@Description  Initiates the Google OAuth 2.0 flow. Sets an HttpOnly SameSite=Lax cookie binding the CSRF state to the browser, then redirects (302) to Google's consent screen.
//	@Tags         OAuth
//	@Produce      json
//	@Success      302  "Redirect to Google consent screen"
//	@Failure      429  {object}  swagger.ErrorEnvelope
//	@Failure      500  {object}  swagger.ErrorEnvelope
//	@Failure      501  {object}  swagger.ErrorEnvelope  "Google sign-in not configured"
//	@Router       /api/v1/auth/google/login [get]
//
// GoogleLogin initiates the Google OAuth 2.0 flow: stage the challenge, bind
// the state to the browser with an HttpOnly cookie, and redirect (302) to
// Google's consent screen.
func (h *OAuthHandler) GoogleLogin(c *gin.Context) {
	state, url, err := h.svc.BeginLogin(c.Request.Context())
	if err != nil {
		response.Respond(c, http.StatusInternalServerError, "failed to initiate oauth", nil)
		return
	}
	if url == "" {
		response.Respond(c, http.StatusNotImplemented, "google sign-in is not configured", nil)
		return
	}
	// Double-submit binding: SameSite=Lax still delivers the cookie on the
	// top-level GET navigation back from Google's redirect.
	secure := c.Request.TLS != nil || c.Request.Header.Get("X-Forwarded-Proto") == "https"
	c.SetCookie(OAuthStateCookie, state, oauthStateCookieMaxAge,
		"/api/v1/auth/google", "", secure, true /* HttpOnly */)
	c.SetSameSite(http.SameSiteLaxMode)
	c.Redirect(http.StatusFound, url)
}

// GoogleCallback godoc
//
//	@Summary      Handle the Google OAuth callback
//	@Description  Handles the redirect back from Google. Verifies the browser-bound state cookie, exchanges the authorization code, verifies the Google ID token, and links/creates the user account. Response shapes are identical to POST /auth/login: HTTP 200 with message "login successful" and the standard token pair, or HTTP 200 with message "mfa required" and data {mfaRequired: true, mfaToken: "<mfa_pending JWT>"} when TOTP is enabled.
//	@Tags         OAuth
//	@Produce      json
//	@Param        code   query  string  true  "Authorization code from Google"
//	@Param        state  query  string  true  "CSRF state parameter"
//	@Success      200  {object}  swagger.LoginEnvelope  "Standard token pair, or the MFA-pending payload when TOTP is enabled (see description)"
//	@Failure      400  {object}  swagger.ErrorEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      429  {object}  swagger.ErrorEnvelope
//	@Failure      501  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/google/callback [get]
//
// GoogleCallback handles the redirect back from Google. It verifies the
// browser-bound state cookie, consumes the server-side challenge, exchanges
// the authorization code, verifies the ID token, links/creates the user
// account, and delegates MFA enforcement. The response shapes are identical
// to POST /auth/login (full tokens or mfa_pending).
func (h *OAuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		response.Respond(c, http.StatusBadRequest, "missing code or state parameter", nil)
		return
	}
	// Browser-binding check BEFORE anything else: the query state must match
	// the cookie this origin set during /google/login.
	cookieState, err := c.Cookie(OAuthStateCookie)
	if err != nil || cookieState != state {
		response.Respond(c, http.StatusUnauthorized, "invalid or expired oauth state", nil)
		return
	}
	clearOAuthStateCookie(c)

	pair, profile, mfaPending, err := h.svc.HandleCallback(
		c.Request.Context(), code, state,
		clientIP(c), c.Request.UserAgent(),
	)
	if err != nil {
		respondError(c, err)
		return
	}
	if mfaPending != nil {
		response.Respond(c, http.StatusOK, "mfa required", mfaPending)
		return
	}
	response.Respond(c, http.StatusOK, "login successful", LoginResponse{Profile: profile, TokenPair: pair})
}

// clearOAuthStateCookie expires the binding cookie — the state is single-use
// and the cookie must not outlive it.
func clearOAuthStateCookie(c *gin.Context) {
	secure := c.Request.TLS != nil || c.Request.Header.Get("X-Forwarded-Proto") == "https"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(OAuthStateCookie, "", -1, "/api/v1/auth/google", "", secure, true)
}
