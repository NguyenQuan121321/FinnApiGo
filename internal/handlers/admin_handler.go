package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/gin-gonic/gin"
)

type AdminServiceInterface interface {
	ListUsers(ctx context.Context, page, limit int, search string) ([]services.UserProfile, int64, error)
	LockUser(ctx context.Context, adminID, targetUserID uint, lockDuration time.Duration, ip string) error
	UnlockUser(ctx context.Context, adminID, targetUserID uint, ip string) error
	ForceLogout(ctx context.Context, adminID, targetUserID uint, ip string) error
	ListTenantSessions(ctx context.Context) ([]services.SessionInfo, error)
	ExportAuditLogs(ctx context.Context, format string) ([]byte, string, error)
}

type AdminHandler struct {
	svc AdminServiceInterface
}

func NewAdminHandler(svc AdminServiceInterface) *AdminHandler {
	return &AdminHandler{svc: svc}
}

// ListUsers godoc
// @Summary List users in tenant (P2.3)
func (h *AdminHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	search := c.Query("search")

	users, total, err := h.svc.ListUsers(c.Request.Context(), page, limit, search)
	if err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "users retrieved", gin.H{
		"items": users,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

type lockUserRequest struct {
	DurationSeconds int64 `json:"durationSeconds"`
}

// LockUser godoc
// @Summary Lock a user account (P2.3)
func (h *AdminHandler) LockUser(c *gin.Context) {
	adminID, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	targetIDParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Respond(c, http.StatusBadRequest, "invalid user id", nil)
		return
	}

	var req lockUserRequest
	_ = c.ShouldBindJSON(&req)

	dur := time.Duration(req.DurationSeconds) * time.Second
	if err := h.svc.LockUser(c.Request.Context(), adminID, uint(targetIDParsed), dur, c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "user locked", nil)
}

// UnlockUser godoc
// @Summary Unlock a user account (P2.3)
func (h *AdminHandler) UnlockUser(c *gin.Context) {
	adminID, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	targetIDParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Respond(c, http.StatusBadRequest, "invalid user id", nil)
		return
	}

	if err := h.svc.UnlockUser(c.Request.Context(), adminID, uint(targetIDParsed), c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "user unlocked", nil)
}

// ForceLogout godoc
// @Summary Force revoke all sessions and tokens of a user (P2.3)
func (h *AdminHandler) ForceLogout(c *gin.Context) {
	adminID, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	targetIDParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Respond(c, http.StatusBadRequest, "invalid user id", nil)
		return
	}

	if err := h.svc.ForceLogout(c.Request.Context(), adminID, uint(targetIDParsed), c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "user logged out of all devices", nil)
}

// ListSessions godoc
// @Summary List all active sessions in tenant (P2.3)
func (h *AdminHandler) ListSessions(c *gin.Context) {
	sessions, err := h.svc.ListTenantSessions(c.Request.Context())
	if err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "tenant sessions retrieved", sessions)
}

// ExportAuditLog godoc
// @Summary Stream export audit logs in CSV or NDJSON (P2.3)
func (h *AdminHandler) ExportAuditLog(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	data, contentType, err := h.svc.ExportAuditLogs(c.Request.Context(), format)
	if err != nil {
		respondError(c, err)
		return
	}

	c.Header("Content-Disposition", `attachment; filename="audit_export.`+format+`"`)
	c.Data(http.StatusOK, contentType, data)
}
