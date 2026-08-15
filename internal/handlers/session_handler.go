package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// SessionService is the narrow service surface the session endpoints need.
// Declared locally (like the other handler interfaces) so the handler can be
// unit-tested with a fake, decoupled from the concrete service.
type SessionService interface {
	ListSessions(ctx context.Context, userID uint) ([]services.SessionInfo, error)
	RevokeSession(ctx context.Context, id, userID uint, ip string) error
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

// List handles GET /api/v1/auth/sessions — returns the caller's active
// (non-expired, non-revoked) sessions/devices.
func (h *SessionHandler) List(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	sessions, err := h.svc.ListSessions(c.Request.Context(), uid)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "sessions fetched", gin.H{"sessions": sessions})
}

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

// parseSessionID reads the :id path param as an unsigned int. Returns
// (0, false) on missing/non-numeric/oversized input so the caller can emit a
// clean 400. Manual parsing (no strconv) keeps this allocation-free on the
// hot path.
func parseSessionID(c *gin.Context) (uint, bool) {
	raw := strings.TrimSpace(c.Param("id"))
	if raw == "" {
		return 0, false
	}
	var n uint64
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, false
		}
		// Overflow guard: reject anything that cannot fit in 64 bits — real
		// autoincrement session ids never approach this magnitude.
		if n > (1<<63)/10 {
			return 0, false
		}
		n = n*10 + uint64(r-'0')
	}
	if n == 0 || n > 1<<63 {
		return 0, false
	}
	return uint(n), true
}
