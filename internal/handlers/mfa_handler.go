package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// MFAHandler exposes the OTP endpoints under /api/v1/auth/mfa.
type MFAService interface {
	SendOTP(context.Context, services.OTPSendInput, string) error
	VerifyOTP(context.Context, services.OTPVerifyInput, string) error
}

type MFAHandler struct {
	svc MFAService
}

func NewMFAHandler(svc MFAService) *MFAHandler {
	return &MFAHandler{svc: svc}
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
