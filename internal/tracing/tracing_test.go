package tracing

import (
	"context"
	"testing"
	"time"
)

func TestSetup_UnsetEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Setup(context.Background())
	if err != nil {
		t.Fatalf("Setup with unset endpoint failed: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("no-op shutdown failed: %v", err)
	}
}

func TestSetup_WithEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	shutdown, err := Setup(ctx)
	if err != nil {
		t.Fatalf("Setup with endpoint failed: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestSetup_InvalidEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Setup(ctx)
	if err == nil {
		t.Fatal("expected error with canceled context")
	}
}
