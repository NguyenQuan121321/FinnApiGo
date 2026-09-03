package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// SessionService is the narrow service surface the session endpoints need.
// Declared locally (like the other handler interfaces) so the handler can be
// unit-tested with a fake, decoupled from the concrete service.
type SessionService interface {
	ListSessions(ctx context.Context, userID uint, currentSID string) ([]services.SessionInfo, error)
	RevokeSession(ctx context.Context, sessionID string, userID uint, ip string) error
}

// SessionHandler exposes the session/device-management endpoints under
// /api/v1/auth/sessions (all behind AuthMiddleware).
type SessionHandler struct {
	svc SessionService
}

// NewSessionHandler constructs a SessionHandler.
func NewSessionHandler(svc SessionService) *SessionHandler {
	return &SessionHandler{svc: svc}
}

// List godoc
//
//	@Summary      List active sessions
//	@Description  Lists the caller's active (non-expired, non-revoked) sessions/devices.
//	@Tags         Sessions
//	@Security     BearerAuth
//	@Produce      json
//	@Success      200  {object}  swagger.SessionsEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/sessions [get]
//
// List handles GET /api/v1/auth/sessions — returns the caller's active
// (non-expired, non-revoked) sessions/devices.
func (h *SessionHandler) List(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	currentSID := c.GetString(middleware.CtxSID)
	sessions, err := h.svc.ListSessions(c.Request.Context(), uid, currentSID)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "sessions fetched", gin.H{"sessions": sessions})
}

// Revoke godoc
//
//	@Summary      Revoke a session
//	@Description  Revokes a single session by ID, scoped to the caller. The target device can no longer rotate its refresh token.
//	@Tags         Sessions
//	@Security     BearerAuth
//	@Produce      json
//	@Param        id  path  string  true  "Session ID (UUID)"
//	@Success      200  {object}  swagger.NullDataEnvelope
//	@Failure      400  {object}  swagger.ErrorEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      404  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/sessions/{id} [delete]
//
// Revoke handles DELETE /api/v1/auth/sessions/:id — revokes a single session
// (device), instantly blocking that device from rotating its refresh token.
func (h *SessionHandler) Revoke(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	id, ok := parseSessionID(c)
	if !ok {
		response.Respond(c, http.StatusBadRequest, "invalid session id", nil)
		return
	}
	if err := h.svc.RevokeSession(c.Request.Context(), id, uid, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "session revoked", nil)
}

// parseSessionID reads the :id path param as a string (UUID or legacy numeric ID).
// Returns ("", false) on empty or oversized input so the caller can emit a clean 400.
func parseSessionID(c *gin.Context) (string, bool) {
	raw := strings.TrimSpace(c.Param("id"))
	if raw == "" || len(raw) > 64 {
		return "", false
	}
	return raw, true
}
