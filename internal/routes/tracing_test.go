package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/tracing"
)

// TestTracing_TraceparentPropagatesIntoRequestLog_O2 — the O2 phase gate:
// with tracing enabled, an incoming traceparent header becomes the request
// span's context, and the request LOG LINE carries the same trace ID (plus
// span_id) so logs and traces correlate.
func TestTracing_TraceparentPropagatesIntoRequestLog_O2(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Real SDK provider so spans are recording; exporter-less is fine (spans
	// just end without export) — the log enrichment reads the span context.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	_ = tracing.ServiceName // ensure the package contract stays referenced

	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Incoming trace: fixed 32-hex trace id, span id 16-hex.
	traceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	spanID := "00f067aa0ba902b7"
	traceparent := "00-" + traceID + "-" + spanID + "-01"

	r := Register(Deps{
		Auth:      handlers.NewAuthHandler(nil, nil),
		RateLimit: middleware.NewRateLimiter(100, 200, time.Minute),
		Tracing:   true,
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", traceparent)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("O2: healthz status %d, want 200", w.Code)
	}

	// The LAST "request" log line must carry the propagated trace ID.
	var rec map[string]any
	found := false
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if !strings.Contains(line, `"request"`) {
			continue
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("O2: log line is not JSON: %v — %s", err, line)
		}
		if rec["trace_id"] == traceID && rec["span_id"] != nil && rec["span_id"] != spanID {
			// Child span of the remote span: same trace, new span id.
			found = true
		}
	}
	if !found {
		t.Fatalf("O2: request log line missing propagated trace_id %s (span_id != %s): %s",
			traceID, spanID, logBuf.String())
	}
}

// TestTracing_NoTraceFieldsWithoutTracing_O2 — with Tracing disabled and no
// incoming span, the log line must not invent trace fields.
func TestTracing_NoTraceFieldsWithoutTracing_O2(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	r := Register(Deps{
		Auth:      handlers.NewAuthHandler(nil, nil),
		RateLimit: middleware.NewRateLimiter(100, 200, time.Minute),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if strings.Contains(logBuf.String(), "trace_id") {
		t.Fatalf("O2: trace_id must be absent without tracing: %s", logBuf.String())
	}
}
