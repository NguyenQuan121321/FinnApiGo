package handlers

import (
	"context"
	"math"
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
//
//	@Summary      List tenant users
//	@Description  Returns a paginated list of users within the current tenant.
//	@Tags         Admin
//	@Security     BearerAuth
//	@Produce      json
//	@Param        page   query     int     false  "Page number"
//	@Param        limit  query     int     false  "Page limit"
//	@Param        search query     string  false  "Search term"
//	@Success      200    {object}  swagger.AdminUsersEnvelope
//	@Failure      401    {object}  swagger.ErrorEnvelope
//	@Failure      403    {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/admin/users [get]
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
	DurationSeconds int64 `json:"durationSeconds" example:"3600"`
}

// LockUser godoc
//
//	@Summary      Lock user account
//	@Description  Locks a user account for a specified duration or indefinitely.
//	@Tags         Admin
//	@Security     BearerAuth
//	@Accept       json
//	@Produce      json
//	@Param        id    path      int              true  "Target user ID"
//	@Param        body  body      lockUserRequest  true  "Lock duration parameters"
//	@Success      200   {object}  swagger.NullDataEnvelope
//	@Failure      400   {object}  swagger.ErrorEnvelope
//	@Failure      401   {object}  swagger.ErrorEnvelope
//	@Failure      403   {object}  swagger.ErrorEnvelope
//	@Failure      404   {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/admin/users/{id}/lock [post]
func (h *AdminHandler) LockUser(c *gin.Context) {
	adminID, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	targetIDParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || targetIDParsed > math.MaxUint {
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
//
//	@Summary      Unlock user account
//	@Description  Unlocks a user account and resets failed login counters.
//	@Tags         Admin
//	@Security     BearerAuth
//	@Produce      json
//	@Param        id   path      int  true  "Target user ID"
//	@Success      200  {object}  swagger.NullDataEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      404  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/admin/users/{id}/unlock [post]
func (h *AdminHandler) UnlockUser(c *gin.Context) {
	adminID, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	targetIDParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || targetIDParsed > math.MaxUint {
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
//
//	@Summary      Force logout user
//	@Description  Revokes all active sessions, refresh tokens, and access tokens for a user.
//	@Tags         Admin
//	@Security     BearerAuth
//	@Produce      json
//	@Param        id   path      int  true  "Target user ID"
//	@Success      200  {object}  swagger.NullDataEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      404  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/admin/users/{id}/force-logout [post]
func (h *AdminHandler) ForceLogout(c *gin.Context) {
	adminID, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	targetIDParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || targetIDParsed > math.MaxUint {
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
//
//	@Summary      List tenant sessions
//	@Description  Lists all active user sessions within the tenant.
//	@Tags         Admin
//	@Security     BearerAuth
//	@Produce      json
//	@Success      200  {object}  swagger.AdminSessionsEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/admin/sessions [get]
func (h *AdminHandler) ListSessions(c *gin.Context) {
	sessions, err := h.svc.ListTenantSessions(c.Request.Context())
	if err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "tenant sessions retrieved", sessions)
}

// ExportAuditLog godoc
//
//	@Summary      Export audit logs
//	@Description  Exports tenant security audit logs in CSV or NDJSON format.
//	@Tags         Admin
//	@Security     BearerAuth
//	@Produce      text/csv,application/x-ndjson
//	@Param        format  query     string  false  "Output format (csv or ndjson)"
//	@Success      200     {string}  string  "Audit export data stream"
//	@Failure      401     {object}  swagger.ErrorEnvelope
//	@Failure      403     {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/admin/audit-log/export [get]
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
