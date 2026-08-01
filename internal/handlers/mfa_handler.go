package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/utils"
)

// MFAHandler exposes the OTP endpoints under /api/v1/auth/mfa.
type MFAHandler struct {
	svc *services.MFAService
}

func NewMFAHandler(svc *services.MFAService) *MFAHandler {
	return &MFAHandler{svc: svc}
}

// SendOTP godoc
// @Summary      Send an OTP code
// @Description  Generate a 6-digit OTP and deliver it (email/SMS/console)
// @Tags         mfa
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      OTPSendRequest  true  "OTP purpose"
// @Success      200   {object}  utils.APIResponse
// @Failure      400,404  {object}  utils.APIResponse
// @Router       /auth/mfa/send-otp [post]
func (h *MFAHandler) SendOTP(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		utils.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req OTPSendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	// Default purpose to login if omitted-ish — but binding requires it; here
	// we just sanity-check it's one of the known purposes.
	if !isValidPurpose(req.Purpose) {
		utils.Respond(c, http.StatusBadRequest, "invalid purpose", nil)
		return
	}
	if err := h.svc.SendOTP(c.Request.Context(), services.OTPSendInput{
		UserID: uid, Purpose: req.Purpose,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "OTP sent", nil)
}

// VerifyOTP godoc
// @Summary      Verify an OTP code
// @Description  Validate the submitted OTP against the stored hash and expiry
// @Tags         mfa
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      OTPVerifyRequest  true  "OTP code + purpose"
// @Success      200   {object}  utils.APIResponse
// @Failure      400,401,429  {object}  utils.APIResponse
// @Router       /auth/mfa/verify-otp [post]
func (h *MFAHandler) VerifyOTP(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		utils.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req OTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if !isValidPurpose(req.Purpose) {
		utils.Respond(c, http.StatusBadRequest, "invalid purpose", nil)
		return
	}
	if err := h.svc.VerifyOTP(c.Request.Context(), services.OTPVerifyInput{
		UserID: uid, Code: req.Code, Purpose: req.Purpose,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "OTP verified", nil)
}

func isValidPurpose(p string) bool {
	switch p {
	case models.OTPPurposeLogin, models.OTPPurposeVerifyEmail, models.OTPPurposeResetPassword:
		return true
	}
	return false
}
