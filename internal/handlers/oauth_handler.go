package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// OAuthService is the handler-layer contract for the Google OAuth flow.
// Each method corresponds to one HTTP endpoint; the handler never touches
// the database or OAuth HTTP calls directly.
type OAuthService interface {
	GenerateState(ctx context.Context) (string, error)
	AuthorizationURL(state string) string
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

// GoogleLogin initiates the Google OAuth 2.0 flow. It generates a CSRF-protected
// state parameter, stores it server-side, and redirects (302) the user to
// Google's consent screen.
func (h *OAuthHandler) GoogleLogin(c *gin.Context) {
	state, err := h.svc.GenerateState(c.Request.Context())
	if err != nil {
		response.Respond(c, http.StatusInternalServerError, "failed to initiate oauth", nil)
		return
	}
	url := h.svc.AuthorizationURL(state)
	if url == "" {
		response.Respond(c, http.StatusNotImplemented, "google sign-in is not configured", nil)
		return
	}
	c.Redirect(http.StatusFound, url)
}

// GoogleCallback handles the redirect back from Google. It validates the CSRF
// state, exchanges the authorization code for tokens, verifies the ID token,
// links/creates the user account, and delegates MFA enforcement. The response
// shapes are identical to POST /auth/login (full tokens or mfa_pending).
func (h *OAuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		response.Respond(c, http.StatusBadRequest, "missing code or state parameter", nil)
		return
	}

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
