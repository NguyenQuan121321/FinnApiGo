package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/google/uuid"
)

var (
	ErrWebhookSSRFBlocked = errors.New("webhook destination address is restricted (SSRF protection)")
	ErrInvalidWebhookURL  = errors.New("invalid webhook URL: must be valid http or https")
)

// WebhookRepo abstracts persistence for webhook endpoints and deliveries (P2.5).
type WebhookRepo interface {
	CreateEndpoint(ctx context.Context, ep *models.WebhookEndpoint) error
	FindActiveEndpointsByEvent(ctx context.Context, tenantID, event string) ([]models.WebhookEndpoint, error)
	CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error
	GetPendingDeliveries(ctx context.Context, limit int) ([]models.WebhookDelivery, error)
	UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry *time.Time, respStatus *int, errMsg string) error
}

// WebhookService manages outbox event queueing and async HTTP delivery (P2.5).
type WebhookService struct {
	repo           WebhookRepo
	httpClient     *http.Client
	allowLocalhost bool
	stopCh         chan struct{}
	wg             sync.WaitGroup
}

func NewWebhookService(repo WebhookRepo) *WebhookService {
	return &WebhookService{
		repo: repo,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		allowLocalhost: false,
		stopCh:         make(chan struct{}),
	}
}

// SetAllowLocalhost enables/disables localhost targets (intended for test fixtures).
func (s *WebhookService) SetAllowLocalhost(allow bool) {
	s.allowLocalhost = allow
}

// ValidateURL performs anti-SSRF IP screening on destination webhook URLs.
func (s *WebhookService) ValidateURL(targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ErrInvalidWebhookURL
	}
	if s.allowLocalhost {
		return nil
	}

	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return ErrWebhookSSRFBlocked
		}
	}
	return nil
}

// RegisterEndpoint registers a new webhook subscription.
func (s *WebhookService) RegisterEndpoint(ctx context.Context, tenantID, targetURL, events string) (*models.WebhookEndpoint, error) {
	if err := s.ValidateURL(targetURL); err != nil {
		return nil, err
	}

	secretBytes := make([]byte, 32)
	_, _ = rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)

	ep := &models.WebhookEndpoint{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		URL:       targetURL,
		Secret:    secret,
		Events:    events,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.repo.CreateEndpoint(ctx, ep); err != nil {
		return nil, err
	}
	return ep, nil
}

// EnqueueEvent queues an event into the outbox for all matching endpoints.
func (s *WebhookService) EnqueueEvent(ctx context.Context, tenantID, event string, data any) error {
	if s.repo == nil {
		return nil
	}
	endpoints, err := s.repo.FindActiveEndpointsByEvent(ctx, tenantID, event)
	if err != nil || len(endpoints) == 0 {
		return err
	}

	payloadMap := map[string]any{
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"tenantId":  tenantID,
		"data":      data,
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return err
	}
	payloadStr := string(payloadBytes)

	for _, ep := range endpoints {
		delivery := &models.WebhookDelivery{
			ID:         uuid.New().String(),
			EndpointID: ep.ID,
			Event:      event,
			Payload:    payloadStr,
			Status:     "pending",
			Attempts:   0,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		_ = s.repo.CreateDelivery(ctx, delivery)
	}
	return nil
}

// SignPayload computes HMAC-SHA256 signature for webhook payload.
func SignPayload(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// DeliverOne sends a single delivery to its target endpoint.
func (s *WebhookService) DeliverOne(ctx context.Context, d *models.WebhookDelivery, secret, targetURL string) error {
	if err := s.ValidateURL(targetURL); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBufferString(d.Payload))
	if err != nil {
		return err
	}

	signature := SignPayload(secret, d.Payload)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-256", signature)
	req.Header.Set("X-Event", d.Event)
	req.Header.Set("X-Delivery-ID", d.ID)

	resp, err := s.httpClient.Do(req)
	d.Attempts++
	if err != nil {
		var nextRetry *time.Time
		status := "pending"
		if d.Attempts >= 5 {
			status = "failed"
		} else {
			retry := time.Now().Add(time.Duration(1<<d.Attempts) * time.Minute)
			nextRetry = &retry
		}
		_ = s.repo.UpdateDeliveryStatus(ctx, d.ID, status, d.Attempts, nextRetry, nil, err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_ = s.repo.UpdateDeliveryStatus(ctx, d.ID, "delivered", d.Attempts, nil, &resp.StatusCode, "")
		return nil
	}

	var nextRetry *time.Time
	status := "pending"
	if d.Attempts >= 5 {
		status = "failed"
	} else {
		retry := time.Now().Add(time.Duration(1<<d.Attempts) * time.Minute)
		nextRetry = &retry
	}
	errMsg := fmt.Sprintf("HTTP %d", resp.StatusCode)
	_ = s.repo.UpdateDeliveryStatus(ctx, d.ID, status, d.Attempts, nextRetry, &resp.StatusCode, errMsg)
	return fmt.Errorf("webhook failed: %s", errMsg)
}
