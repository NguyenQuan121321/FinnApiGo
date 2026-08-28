package metrics

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/finnapigo/finnapigo/internal/services"
)

// TestMetrics_TokenGate_401WithoutBearer_X1 — the phase gate: with
// METRICS_TOKEN configured, a request without the bearer token is rejected.
func TestMetrics_TokenGate_401WithoutBearer_X1(t *testing.T) {
	token := "x1-" + "metrics-token-value"
	h := BearerAuth(token, Handler(nil))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("X1: no bearer token → status %d, want 401", w.Code)
	}

	// With the correct bearer token the scrape succeeds.
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("X1: valid bearer token → status %d, want 200", w.Code)
	}

	// A WRONG token is also rejected.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-value")
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("X1: wrong bearer token → status %d, want 401", w.Code)
	}
}

// TestMetrics_TokenGate_NoTokenOpen_X1 — without METRICS_TOKEN the handler
// stays open (the token is optional; the internal listener is the control).
func TestMetrics_TokenGate_NoTokenOpen_X1(t *testing.T) {
	h := BearerAuth("", Handler(nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("X1: no token configured → status %d, want 200", w.Code)
	}
}

// TestMetrics_AuthOutcomeCountersExposed_O3 — the O3 gate: the fine-grained
// auth counters surface on the scrape endpoint under the v2 P2 naming, with
// values matching the underlying atomics (label-free, G2).
func TestMetrics_AuthOutcomeCountersExposed_O3(t *testing.T) {
	before := services.LoginFailures.Load()
	services.LoginFailures.Add(3)

	w := httptest.NewRecorder()
	Handler(nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()

	for _, name := range []string{
		"finnapigo_login_success_total",
		"finnapigo_login_failure_total",
		"finnapigo_refresh_rotations_total",
		"finnapigo_token_reuse_detections_total",
		"finnapigo_totp_failure_total",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("O3: metric %s missing from scrape output", name)
		}
	}
	want := "finnapigo_login_failure_total " + itoa(int(before+3))
	if !strings.Contains(body, want) {
		t.Fatalf("O3: %s wrong value, want suffix %q in:\n%s", name("login"), want, body)
	}
}

func itoa(n int) string { return strconv.FormatInt(int64(n), 10) }
func name(string) string { return "" }
