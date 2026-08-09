package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// MFAHandler exposes the OTP endpoints under /api/v1/auth/mfa.
type MFAService interface {
	SendOTP(context.Context, services.OTPSendInput, string) error
	VerifyOTP(context.Context, services.OTPVerifyInput, string) error
}

type TOTPService interface {
	Enable(context.Context, uint, string) (string, string, error)
	VerifyEnable(context.Context, uint, string) ([]string, error)
	Validate(context.Context, uint, string) error
}

type MFAHandler struct {
	svc  MFAService
	totp TOTPService
}

func NewMFAHandler(svc MFAService, totp ...TOTPService) *MFAHandler {
	h := &MFAHandler{svc: svc}
	if len(totp) > 0 {
		h.totp = totp[0]
	}
	return h
}

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
	secret, uri, err := h.totp.Enable(c.Request.Context(), uid, account)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "TOTP enrollment pending verification", gin.H{"secret": secret, "provisioningURI": uri})
}

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

func (h *MFAHandler) SendOTP(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req OTPSendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	// Default purpose to login if omitted-ish — but binding requires it; here
	// we just sanity-check it's one of the known purposes.
	if !isValidPurpose(req.Purpose) {
		response.Respond(c, http.StatusBadRequest, "invalid purpose", nil)
		return
	}
	if err := h.svc.SendOTP(c.Request.Context(), services.OTPSendInput{
		UserID: uid, Purpose: req.Purpose,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "OTP sent", nil)
}

func (h *MFAHandler) VerifyOTP(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req OTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if !isValidPurpose(req.Purpose) {
		response.Respond(c, http.StatusBadRequest, "invalid purpose", nil)
		return
	}
	if err := h.svc.VerifyOTP(c.Request.Context(), services.OTPVerifyInput{
		UserID: uid, Code: req.Code, Purpose: req.Purpose,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "OTP verified", nil)
}

func isValidPurpose(p string) bool {
	switch p {
	case models.OTPPurposeLogin, models.OTPPurposeVerifyEmail, models.OTPPurposeResetPassword:
		return true
	}
	return false
}
