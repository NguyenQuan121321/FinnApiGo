package handlers

import (
	"context"
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
// @Summary List trusted devices for the user (P2.4)
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
// @Summary Revoke a trusted device (P2.4)
func (h *TrustedDeviceHandler) RevokeDevice(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}

	idParsed, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Respond(c, http.StatusBadRequest, "invalid device id", nil)
		return
	}

	if err := h.svc.Revoke(c.Request.Context(), uint(idParsed), uid); err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusOK, "trusted device revoked", nil)
}
