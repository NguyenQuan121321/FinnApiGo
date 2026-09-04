// Package tracing wires distributed tracing (O1) behind the standard
// OTLP endpoint variable. With OTEL_EXPORTER_OTLP_ENDPOINT unset the global
// tracer provider stays the SDK's no-op default: otelgin still establishes a
// span context per request (so O2's trace-ID log correlation works, including
// an incoming traceparent), but no spans are recorded or exported and the
// overhead is a context value per request. With the endpoint set, spans are
// batched and exported over OTLP/HTTP with the standard W3C TraceContext
// propagator.
package tracing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

// ServiceName is the OTLP resource service.name for every span this service
// exports.
const ServiceName = "finnapigo"

// Setup configures the global tracer provider + propagator from the
// OTEL_EXPORTER_OTLP_ENDPOINT environment. Returns a shutdown func that
// flushes the batch processor; the caller defers it after the HTTP servers
// have stopped. Unset endpoint => no-op shutdown, nil error.
func Setup(ctx context.Context) (func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	if endpoint == "" {
		slog.Info("tracing: OTEL_EXPORTER_OTLP_ENDPOINT unset — spans are non-recording (zero export overhead)")
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx) // reads OTEL_EXPORTER_OTLP_ENDPOINT + headers itself
	if err != nil {
		return nil, fmt.Errorf("tracing: otlp exporter: %w", err)
	}
	res, err := sdkresource.Merge(
		sdkresource.Default(),
		sdkresource.NewWithAttributes("",
			semconv.ServiceName(ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter,
			sdktrace.WithBatchTimeout(2*time.Second),
			sdktrace.WithMaxExportBatchSize(256),
		)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	slog.Info("tracing: OTLP exporter enabled", "endpoint", endpoint)
	return func(parent context.Context) error {
		shutdownCtx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		return errors.Join(tp.Shutdown(shutdownCtx))
	}, nil
}
