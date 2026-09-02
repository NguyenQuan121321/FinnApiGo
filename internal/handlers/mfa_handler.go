package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/response"
)

// TOTPService is the MFA mechanism exposed under /api/v1/auth/mfa.
type TOTPService interface {
	// Enable starts enrollment. sudoToken (X-Sudo-Token) is only required —
	// and enforced in the service — when rotating an already-ACTIVE device.
	Enable(context.Context, uint, string, string) (string, string, error)
	VerifyEnable(context.Context, uint, string) ([]string, error)
	Validate(context.Context, uint, string) error
	// ViewRecoveryCodes re-displays the saved codes after a current TOTP code.
	ViewRecoveryCodes(context.Context, uint, string) ([]string, error)
	// RegenerateRecoveryCodes invalidates the old set and issues a new one.
	// TOTP/sudo enforcement lives in the route middleware, not the service.
	RegenerateRecoveryCodes(context.Context, uint) ([]string, error)
}

// MFAHandler exposes the TOTP endpoints under /api/v1/auth/mfa.
type MFAHandler struct {
	totp    TOTPService
	jwtMgr  *jwt.JWTManager
	sudoTTL time.Duration
}

// NewMFAHandler constructs the handler. jwtMgr mints the sudo token returned
// by ViewRecoveryCodes; when nil no token is issued (degraded mode for tests
// that don't exercise sudo). sudoTTL <= 0 falls back to 15 minutes.
func NewMFAHandler(totp TOTPService, jwtMgr *jwt.JWTManager, sudoTTL time.Duration) *MFAHandler {
	return &MFAHandler{totp: totp, jwtMgr: jwtMgr, sudoTTL: sudoTTL}
}

// EnableTOTP godoc
//
//	@Summary      Begin TOTP enrollment
//	@Description  Begins TOTP enrollment. Returns the shared secret and provisioning URI. If TOTP is already active, stages a new secret (requires X-Sudo-Token for re-enrollment).
//	@Tags         MFA
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Success      200  {object}  swagger.TOTPEnableEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      429  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/mfa/totp/enable [post]
func (h *MFAHandler) EnableTOTP(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok || h.totp == nil {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	// Prefer the authenticated user's email as the TOTP account name when the
	// auth middleware populated it; fall back to a stable synthetic name so
	// enrollment never fails just because the claim was absent.
	email, _ := c.Get(middleware.CtxEmail)
	account := fmt.Sprintf("user-%d", uid)
	if e, ok := email.(string); ok && e != "" {
		account = e
	}
	// Re-enrolling an active device demands sudo; the header is forwarded and
	// the service enforces it (a bare access token is not enough, C6).
	secret, uri, err := h.totp.Enable(c.Request.Context(), uid, account, c.GetHeader(middleware.SudoHeader))
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "TOTP enrollment pending verification", gin.H{"secret": secret, "provisioningURI": uri})
}

// VerifyTOTP godoc
//
//	@Summary      Confirm TOTP enrollment
//	@Description  Confirms TOTP enrollment with a current code. Activates TOTP and returns single-use recovery codes (displayed once).
//	@Tags         MFA
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        body  body      handlers.TOTPCodeRequest  true  "Current TOTP code"
//	@Success      200   {object}  swagger.RecoveryCodesEnvelope
//	@Failure      400   {object}  swagger.ErrorEnvelope
//	@Failure      401   {object}  swagger.ErrorEnvelope
//	@Failure      429   {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/mfa/totp/verify [post]
func (h *MFAHandler) VerifyTOTP(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok || h.totp == nil {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req TOTPCodeRequest
	if !bindJSON(c, &req) {
		return
	}
	codes, err := h.totp.VerifyEnable(c.Request.Context(), uid, req.Code)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "TOTP enabled", gin.H{"recoveryCodes": codes})
}

// ValidateTOTP godoc
//
//	@Summary      Validate a TOTP code
//	@Description  Validates a TOTP code for re-authentication on an active session.
//	@Tags         MFA
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        body  body      handlers.TOTPCodeRequest  true  "Current TOTP code"
//	@Success      200   {object}  swagger.NullDataEnvelope
//	@Failure      400   {object}  swagger.ErrorEnvelope
//	@Failure      401   {object}  swagger.ErrorEnvelope
//	@Failure      429   {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/mfa/totp/validate [post]
func (h *MFAHandler) ValidateTOTP(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok || h.totp == nil {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req TOTPCodeRequest
	if !bindJSON(c, &req) {
		return
	}
	if err := h.totp.Validate(c.Request.Context(), uid, req.Code); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "TOTP validated", nil)
}

// ViewRecoveryCodes godoc
//
//	@Summary      View recovery codes
//	@Description  Re-displays saved recovery codes after verifying a current TOTP code. Also mints a short-lived sudo token for the regenerate endpoint.
//	@Tags         MFA
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        body  body      handlers.TOTPCodeRequest  true  "Current TOTP code"
//	@Success      200   {object}  swagger.RecoveryCodesViewEnvelope
//	@Failure      400   {object}  swagger.ErrorEnvelope
//	@Failure      401   {object}  swagger.ErrorEnvelope
//	@Failure      429   {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/mfa/totp/recovery-codes [post]
//
// ViewRecoveryCodes re-displays the caller's saved recovery codes. The request
// must carry a current TOTP code (validated by the service); on success the
// handler also mints a short-lived sudo token so the client can regenerate
// codes within the sudo window without a second TOTP prompt.
func (h *MFAHandler) ViewRecoveryCodes(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok || h.totp == nil {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req TOTPCodeRequest
	if !bindJSON(c, &req) {
		return
	}
	codes, err := h.totp.ViewRecoveryCodes(c.Request.Context(), uid, req.Code)
	if err != nil {
		respondError(c, err)
		return
	}
	resp := gin.H{"recoveryCodes": nonNil(codes)}
	if h.jwtMgr != nil {
		ttl := h.sudoTTL
		if ttl <= 0 {
			ttl = 15 * time.Minute
		}
		sudo, err := h.jwtMgr.Issue(uid, ctxString(c, middleware.CtxRole), ctxString(c, middleware.CtxEmail), jwt.TokenTypeSudo, ttl)
		if err != nil {
			respondError(c, err)
			return
		}
		resp["sudoToken"] = sudo
		resp["sudoExpiresInSec"] = int(ttl.Seconds())
	}
	response.Respond(c, http.StatusOK, "Recovery codes", resp)
}

// RegenerateRecoveryCodes godoc
//
//	@Summary      Regenerate recovery codes
//	@Description  Invalidates existing recovery codes and generates a new set. Requires the X-Sudo-Token minted by the view-recovery-codes endpoint (GitHub-style sudo mode).
//	@Tags         MFA
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Security     SudoAuth
//	@Success      200  {object}  swagger.RecoveryCodesEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      429  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/mfa/totp/recovery-codes/regenerate [post]
//
// RegenerateRecoveryCodes invalidates the caller's existing recovery codes and
// returns a brand-new set. Sudo enforcement (X-Sudo-Token bound to the current
// user) happens in the route middleware before this handler runs.
func (h *MFAHandler) RegenerateRecoveryCodes(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok || h.totp == nil {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	codes, err := h.totp.RegenerateRecoveryCodes(c.Request.Context(), uid)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "New recovery codes generated", gin.H{"recoveryCodes": nonNil(codes)})
}

// ctxString reads a string-valued context key set by the auth middleware.
func ctxString(c *gin.Context, key string) string {
	v, ok := c.Get(key)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// nonNil keeps JSON arrays from serializing as null when empty.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
