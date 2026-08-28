package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
