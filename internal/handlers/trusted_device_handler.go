package handlers

import (
	"context"
	"math"
	"net/http"
	"strconv"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/gin-gonic/gin"
)

type TrustedDeviceServiceInterface interface {
	ListByUser(ctx context.Context, userID uint) ([]services.TrustedDeviceInfo, error)
	Revoke(ctx context.Context, id, userID uint) error
}

type TrustedDeviceHandler struct {
	svc TrustedDeviceServiceInterface
}

func NewTrustedDeviceHandler(svc TrustedDeviceServiceInterface) *TrustedDeviceHandler {
	return &TrustedDeviceHandler{svc: svc}
}

// ListDevices godoc
//
//	@Summary      List trusted devices
//	@Description  Lists caller's active trusted devices eligible for 30-day MFA bypass.
//	@Tags         TrustedDevices
//	@Security     BearerAuth
//	@Produce      json
//	@Success      200  {object}  swagger.TrustedDevicesListEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/trusted-devices [get]
func (h *TrustedDeviceHandler) ListDevices(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	devices, err := h.svc.ListByUser(c.Request.Context(), uid)
	if err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "trusted devices retrieved", devices)
}

// RevokeDevice godoc
//
//	@Summary      Revoke trusted device
//	@Description  Revokes MFA bypass trust for a specific device.
//	@Tags         TrustedDevices
//	@Security     BearerAuth
//	@Produce      json
//	@Param        id   path      int  true  "Device ID"
//	@Success      200  {object}  swagger.NullDataEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      404  {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/trusted-devices/{id} [delete]
func (h *TrustedDeviceHandler) RevokeDevice(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	idParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || idParsed > math.MaxUint {
		response.Respond(c, http.StatusBadRequest, "invalid device id", nil)
		return
	}

	if err := h.svc.Revoke(c.Request.Context(), uint(idParsed), uid); err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "trusted device revoked", nil)
}
