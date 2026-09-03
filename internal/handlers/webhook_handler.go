package handlers

import (
	"context"
	"net/http"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/gin-gonic/gin"
)

type WebhookServiceInterface interface {
	RegisterEndpoint(ctx context.Context, tenantID, targetURL, events string) (*models.WebhookEndpoint, error)
}

type WebhookHandler struct {
	svc WebhookServiceInterface
}

func NewWebhookHandler(svc WebhookServiceInterface) *WebhookHandler {
	return &WebhookHandler{svc: svc}
}

type createWebhookRequest struct {
	URL    string `json:"url" binding:"required"`
	Events string `json:"events" binding:"required"`
}

// CreateEndpoint godoc
// @Summary Register a webhook endpoint (P2.5)
func (h *WebhookHandler) CreateEndpoint(c *gin.Context) {
	var req createWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, "invalid request: url and events required", nil)
		return
	}

	tid := tenant.FromContext(c.Request.Context())
	ep, err := h.svc.RegisterEndpoint(c.Request.Context(), tid, req.URL, req.Events)
	if err != nil {
		respondError(c, err)
		return
	}

	response.Respond(c, http.StatusCreated, "webhook endpoint registered", ep)
}
