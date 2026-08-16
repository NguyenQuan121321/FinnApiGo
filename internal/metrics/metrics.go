// Package metrics exposes the Prometheus scrape endpoint with the process /
// Go runtime collectors plus this service's custom availability counters
// (P2). The endpoint is deliberately UNAUTHENTICATED so scrapers need no
// credentials — operators must keep it on an internal interface and never
// expose it publicly (documented in the README).
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
)

// Handler builds the /metrics handler. auditDepth reports the async audit
// writer's current buffer occupancy (nil disables that gauge — e.g. sync
// mode). Counters wrap the atomic metrics the runtime already maintains, so
// registration never races with traffic.
func Handler(auditDepth func() float64) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: "finnapigo", Name: "store_errors_total",
			Help: "Key-value store backend failures (counters failed open, single-use guards failed closed).",
		}, func() float64 { return float64(store.StoreErrors.Load()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: "finnapigo", Name: "audit_entries_dropped_total",
			Help: "Audit entries lost to buffer overflow or failed batch inserts.",
		}, func() float64 { return float64(services.AuditDroppedEntries.Load()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: "finnapigo", Name: "rate_limited_requests_total",
			Help: "Requests rejected with 429 by the shared or local rate limiter.",
		}, func() float64 { return float64(middleware.RateLimitedRequests.Load()) }),
	)
	if auditDepth != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "finnapigo", Name: "audit_buffer_depth",
			Help: "Entries currently buffered by the async audit writer.",
		}, auditDepth))
	}
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
