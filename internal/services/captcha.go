// Package services — CAPTCHA verifiers (§2).
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NoOpCaptchaVerifier always passes — used when CAPTCHA is disabled (default).
type NoOpCaptchaVerifier struct{}

func (NoOpCaptchaVerifier) Verify(ctx context.Context, token string) error { return nil }

// ErrCaptchaRejected is returned when the upstream provider rejects the token.
var ErrCaptchaRejected = errors.New("captcha verification failed")

// TurnstileVerifier verifies a Cloudflare Turnstile token against the
// siteverify endpoint. Used when CAPTCHA_PROVIDER=turnstile.
//
// Docs: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
type TurnstileVerifier struct {
	secret   string
	client   *http.Client
	endpoint string // overridable for tests
}

// NewTurnstileVerifier constructs a verifier. The endpoint defaults to the
// Cloudflare siteverify URL.
func NewTurnstileVerifier(secret string) *TurnstileVerifier {
	return &TurnstileVerifier{
		secret:   secret,
		client:   &http.Client{Timeout: 5 * time.Second},
		endpoint: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	}
}

// WithEndpoint overrides the siteverify endpoint (tests).
func (t *TurnstileVerifier) WithEndpoint(u string) *TurnstileVerifier {
	t.endpoint = u
	return t
}

func (t *TurnstileVerifier) Verify(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrCaptchaRejected
	}
	form := url.Values{}
	form.Set("secret", t.secret)
	form.Set("response", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("turnstile: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("turnstile: decode: %w", err)
	}
	if !result.Success {
		return ErrCaptchaRejected
	}
	return nil
}
