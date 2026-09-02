// Package routes wires the Gin router groups + middlewares + handlers.
package routes

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	otelgin "go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	oteltrace "go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/response"
)

// Deps bundles everything the router needs. Constructed in main.go.
type Deps struct {
	Auth                *handlers.AuthHandler
	OAuth               *handlers.OAuthHandler
	MFA                 *handlers.MFAHandler
	Sessions            *handlers.SessionHandler
	JWT                 *jwt.JWTManager
	RateLimit           *middleware.RateLimiter
	TOTPCluster         *middleware.ConcurrencyLimiter // caps concurrent CPU-bound TOTP validations
	DB                  *gorm.DB                       // optional, for /readyz
	MaxRequestBodyBytes int64                          // §5 — global body-size cap applied BEFORE routes
	// TrustedProxies configures which direct peers may set X-Forwarded-For /
	// X-Real-IP, so c.ClientIP() resolves the real client IP securely behind a
	// reverse proxy (Cloudflare/Nginx). Empty trusts no one (RemoteAddr only).
	TrustedProxies []string
	// HSTSSeconds enables Strict-Transport-Security on HTTPS responses when
	// > 0 (A3). Ignored for plain-HTTP requests.
	HSTSSeconds int
	// Metrics is the Prometheus scrape handler (P2). Nil = /metrics not
	// mounted. Deliberately unauthenticated: keep it internal-facing.
	Metrics http.Handler
	// PwdVersion backs AuthMiddleware's access-token revocation on
	// credential change (A7); typically services.AuthService.CurrentPwdVersion.
	// Nil disables the check.
	PwdVersion middleware.VersionSource
	// Passkey serves the WebAuthn ceremonies (Phase 9). Nil = endpoints not
	// registered (passkeys disabled — the only approved API extension).
	Passkey *handlers.PasskeyHandler
	// Tracing installs the otelgin middleware (O1) so every request carries a
	// span context; O2's request-log enrichment reads it. Enable it whenever
	// a TracerProvider is configured — it is a no-op provider when unset.
	Tracing bool
	// CORSAllowedOrigins is the strict browser-origin allowlist for
	// cross-origin API calls (web frontends, test harnesses). Empty = no
	// CORS behavior.
	CORSAllowedOrigins []string
	// SwaggerEnabled mounts the swag-generated Swagger UI at
	// /swagger/index.html. Defaults to false — must be explicitly enabled.
	// Keep disabled in production unless the documentation endpoint is
	// required by API consumers behind appropriate access controls.
	SwaggerEnabled bool
}

// Register builds the full route tree and returns the configured engine.
// All endpoints live under /api/v1; auth endpoints under /api/v1/auth; MFA
// under /api/v1/auth/mfa — exactly per the prompt's structure.
func Register(deps Deps) *gin.Engine {
	r := gin.New()
	// §Session — securely honor X-Forwarded-For / X-Real-IP ONLY from the
	// configured reverse-proxy CIDRs. When TrustedProxies is empty we trust no
	// peer, so c.ClientIP() returns the direct RemoteAddr (un-spoofable). This
	// drives the client_ip recorded on each session.
	//
	// SetTrustedProxies(nil) means "trust no proxies"; passing the operator's
	// list restricts header trust to exactly those peers.
	_ = r.SetTrustedProxies(deps.TrustedProxies)
	r.Use(gin.Recovery())
	// Browser clients (frontends, test harnesses) on another origin need the
	// allowlisted CORS headers, and their preflight OPTIONS must never fall
	// through to a 404.
	if len(deps.CORSAllowedOrigins) > 0 {
		r.Use(middleware.CORS(deps.CORSAllowedOrigins))
	}
	// O1 — the span must start BEFORE requestLogger so the log line (emitted
	// after c.Next()) can carry the span's trace_id/span_id (O2).
	if deps.Tracing {
		r.Use(otelgin.Middleware("finnapigo"))
	}
	r.Use(requestLogger())
	// A3 — baseline security headers on every response: nosniff, no-referrer,
	// Cache-Control: no-store (this is an auth API — nothing is cacheable),
	// and HSTS on HTTPS responses when configured.
	r.Use(middleware.SecurityHeaders(deps.HSTSSeconds))
	// §5 — global body-size limit. Applied here (before any route group) so it
	// covers every endpoint. Must be in Register, not after, because Gin
	// middlewares registered via Use apply only to routes defined afterwards.
	if deps.MaxRequestBodyBytes > 0 {
		r.Use(func(c *gin.Context) {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, deps.MaxRequestBodyBytes)
			c.Next()
		})
	}

	// Prometheus scrape endpoint (P2) — see Deps.Metrics.
	if deps.Metrics != nil {
		r.GET("/metrics", metricsHandler(deps.Metrics))
	}

	// Swagger UI (gated) — interactive docs generated from swag annotations.
	// Mounted BEFORE the route groups so it shares the global middlewares
	// (security headers, body-size cap, request log). The generated spec is a
	// developer-experience companion; docs/openapi.yaml stays the contract of
	// record enforced by internal/apidrift.
	if deps.SwaggerEnabled {
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// health check — process liveness (no DB dependency).
	r.GET("/healthz", healthz)

	// readiness check — pings DB to confirm the app can serve requests (§7).
	r.GET("/readyz", readyz(deps.DB))

	api := r.Group("/api/v1")
	auth := api.Group("/auth")

	// ---- Public core-auth endpoints (no auth middleware) ----
	auth.POST("/register", deps.RateLimit.Handler(), deps.Auth.Register)
	auth.POST("/login", deps.RateLimit.Handler(), deps.Auth.Login)
	// A5 — refresh/reset/verify are unauthenticated token-consumption
	// endpoints: without the limiter they are free brute-force / replay
	// surfaces (single-use guards reject, but the requests still cost CPU).
	auth.POST("/refresh-token", deps.RateLimit.Handler(), deps.Auth.Refresh)
	auth.POST("/forgot-password", deps.RateLimit.Handler(), deps.Auth.ForgotPassword)
	auth.POST("/reset-password", deps.RateLimit.Handler(), deps.Auth.ResetPassword)
	auth.POST("/verify-email", deps.RateLimit.Handler(), deps.Auth.VerifyEmail)
	auth.POST("/resend-verification", deps.RateLimit.Handler(), deps.Auth.ResendVerifyEmail)

	// ---- Google OAuth 2.0 / OpenID Connect ----
	if deps.OAuth != nil {
		// /google/login mints a store-backed challenge per request — without
		// the limiter it is the one unauthenticated endpoint that grows
		// shared-store state, i.e. a cheap key-flooding DoS vector.
		auth.GET("/google/login", deps.RateLimit.Handler(), deps.OAuth.GoogleLogin)
		auth.GET("/google/callback", deps.RateLimit.Handler(), deps.OAuth.GoogleCallback)
	}

	// ---- Authenticated core-auth endpoints ----
	authed := auth.Group("")
	authed.Use(middleware.AuthMiddleware(deps.JWT, deps.PwdVersion))
	authed.POST("/logout", deps.Auth.Logout)
	authed.POST("/logout-all", deps.Auth.LogoutAll)
	authed.POST("/change-password", deps.Auth.ChangePassword)
	// First password for Google-OAuth-only accounts; the service hard-rejects
	// (409) accounts that already have a password, so it is not a bypass for
	// change-password above.
	authed.POST("/set-password", deps.Auth.SetPassword)
	authed.GET("/me", deps.Auth.Me)

	// ---- Session & device management (authenticated) ----
	// GET    /api/v1/auth/sessions      — list the caller's active devices
	// DELETE /api/v1/auth/sessions/:id  — revoke one device's session
	if deps.Sessions != nil {
		authed.GET("/sessions", deps.Sessions.List)
		authed.DELETE("/sessions/:id", deps.Sessions.Revoke)
	}

	// ---- MFA login-verify (mfa_pending token ONLY) ----
	// POST /api/v1/auth/mfa/login-verify — complete login via TOTP code.
	// Uses MFAPendingMiddleware which accepts ONLY mfa_pending JWTs,
	// rejecting access tokens so a fully-logged-in session cannot call this
	// endpoint to bypass a pending login for a different session.
	mfaPending := auth.Group("/mfa")
	mfaPending.Use(middleware.MFAPendingMiddleware(deps.JWT))
	if deps.TOTPCluster != nil && deps.TOTPCluster.Capacity() > 0 {
		mfaPending.POST("/login-verify", deps.RateLimit.Handler(), deps.TOTPCluster.Handler(), deps.Auth.CompleteMFALogin)
	} else {
		mfaPending.POST("/login-verify", deps.RateLimit.Handler(), deps.Auth.CompleteMFALogin)
	}

	// ---- MFA sub-group (authenticated; TOTP is the only MFA mechanism) ----
	mfa := authed.Group("/mfa")

	// ---- TOTP endpoints (rate-limited + concurrency-gated) ----
	// The concurrency limiter (deps.TOTPCluster) is installed BEFORE the
	// handler so excess CPU-bound validation requests are rejected with 429
	// before they can starve worker threads or saturate the DB pool.
	if deps.TOTPCluster != nil && deps.TOTPCluster.Capacity() > 0 {
		mfa.POST("/totp/enable", deps.RateLimit.Handler(), deps.TOTPCluster.Handler(), deps.MFA.EnableTOTP)
		mfa.POST("/totp/verify", deps.RateLimit.Handler(), deps.TOTPCluster.Handler(), deps.MFA.VerifyTOTP)
		mfa.POST("/totp/validate", deps.RateLimit.Handler(), deps.TOTPCluster.Handler(), deps.MFA.ValidateTOTP)
		mfa.POST("/totp/recovery-codes", deps.RateLimit.Handler(), deps.TOTPCluster.Handler(), deps.MFA.ViewRecoveryCodes)
	} else {
		mfa.POST("/totp/enable", deps.RateLimit.Handler(), deps.MFA.EnableTOTP)
		mfa.POST("/totp/verify", deps.RateLimit.Handler(), deps.MFA.VerifyTOTP)
		mfa.POST("/totp/validate", deps.RateLimit.Handler(), deps.MFA.ValidateTOTP)
		mfa.POST("/totp/recovery-codes", deps.RateLimit.Handler(), deps.MFA.ViewRecoveryCodes)
	}

	// ---- Passkey / WebAuthn (Phase 9 — the ONLY approved API extension) ----
	// POST /api/v1/auth/mfa/passkey/register/challenge + /verify — the
	// registration ceremony (W4). The verify body is the verbatim WebAuthn
	// attestation response, so no body-binding middleware may consume it.
	if deps.Passkey != nil {
		mfa.POST("/passkey/register/challenge", deps.RateLimit.Handler(), deps.Passkey.BeginRegistration)
		mfa.POST("/passkey/register/verify", deps.RateLimit.Handler(), deps.Passkey.FinishRegistration)
		// Authentication ceremony (W5): step-up login with a registered
		// passkey; issues a fresh standard token pair on success.
		mfa.POST("/passkey/authenticate/challenge", deps.RateLimit.Handler(), deps.Passkey.BeginAuthentication)
		mfa.POST("/passkey/authenticate/verify", deps.RateLimit.Handler(), deps.Passkey.FinishAuthentication)
		// Device management (W6): list, and sudo-gated revoke — a stolen
		// access token alone cannot strip a user's credentials.
		mfa.GET("/passkeys", deps.Passkey.List)
		mfa.DELETE("/passkeys/:id", deps.RateLimit.Handler(), middleware.SudoMiddleware(deps.JWT), deps.Passkey.Revoke)
	}

	// ---- Recovery-code regeneration (GitHub-style sudo mode) ----
	// POST /api/v1/auth/mfa/totp/recovery-codes/regenerate — requires the
	// X-Sudo-Token minted by the view endpoint above (which itself demands a
	// current TOTP code), so a stolen access token alone cannot mint fresh
	// recovery codes. No TOTP validation happens here, hence no TOTPCluster.
	mfa.POST("/totp/recovery-codes/regenerate", deps.RateLimit.Handler(), middleware.SudoMiddleware(deps.JWT), deps.MFA.RegenerateRecoveryCodes)

	return r
}

// metricsHandler adapts the Prometheus scrape handler (P2) onto the router.
//
//	@Summary      Prometheus metrics
//	@Description  Prometheus exposition endpoint. Intended for the internal metrics listener (METRICS_ADDR); when served on the public listener it is unauthenticated by design (X1).
//	@Tags         Operational
//	@Produce      plain
//	@Success      200 {string} string "Prometheus text exposition"
//	@Router       /metrics [get]
func metricsHandler(h http.Handler) gin.HandlerFunc {
	return gin.WrapH(h)
}

// healthz reports process liveness — no DB dependency (§7).
//
//	@Summary      Liveness check
//	@Description  Process liveness probe — always 200 while the process is up; no DB dependency.
//	@Tags         Operational
//	@Produce      json
//	@Success      200 {object} swagger.HealthEnvelope
//	@Router       /healthz [get]
func healthz(c *gin.Context) {
	response.Respond(c, 200, "ok", gin.H{"status": "ok"})
}

// readyz reports readiness — pings the DB to confirm the app can serve
// requests (§7). A nil DB (no database configured) reports db "skipped".
//
//	@Summary      Readiness check
//	@Description  Readiness probe — pings the database with a 3s timeout. Responds 503 when the DB is unreachable.
//	@Tags         Operational
//	@Produce      json
//	@Success      200 {object} swagger.HealthEnvelope
//	@Failure      503 {object} swagger.HealthEnvelope "not ready — database unreachable"
//	@Router       /readyz [get]
func readyz(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if db == nil {
			response.Respond(c, 200, "ok", gin.H{"status": "ok", "db": "skipped"})
			return
		}
		sqlDB, err := db.DB()
		if err != nil {
			response.Respond(c, 503, "not ready", gin.H{"status": "error", "db": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := sqlDB.PingContext(ctx); err != nil {
			response.Respond(c, 503, "not ready", gin.H{"status": "error", "db": err.Error()})
			return
		}
		response.Respond(c, 200, "ok", gin.H{"status": "ok", "db": "up"})
	}
}

// requestLogger is a minimal access log (§4 — token redaction). It logs
// method, path, status, latency, and request-ID but NEVER logs the
// Authorization header, refreshToken, token, password, or code fields.
func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		// Propagate or generate X-Request-ID (§7).
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()

		// Log after request completes — safe fields only. client_ip is set
		// after Next() so middlewares that ran earlier (auth denials in
		// particular) read the same resolution via c.ClientIP() themselves.
		status := c.Writer.Status()
		latency := time.Since(start)
		// O2 — correlate the log line with the request span. With tracing
		// enabled (or an incoming traceparent) the fields carry the same
		// trace/span IDs the span exports; otherwise they are omitted.
		args := []any{
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"client_ip", c.ClientIP(),
			"rid", requestID,
		}
		if sc := oteltrace.SpanContextFromContext(c.Request.Context()); sc.IsValid() {
			args = append(args, "trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String())
		}
		// 5xx responses carry the server-side reason — surface it, otherwise
		// an internal failure is invisible behind the bare status code.
		if status >= 500 {
			if len(c.Errors) > 0 {
				args = append(args, "err", c.Errors.String())
			}
			slog.Error("request", args...)
			return
		}
		slog.Info("request", args...)
	}
}

// generateRequestID creates a unique request identifier (UUIDv4).
func generateRequestID() string {
	return uuid.New().String()
}
