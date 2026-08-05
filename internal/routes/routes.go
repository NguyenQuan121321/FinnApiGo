// Package routes wires the Gin router groups + middlewares + handlers.
package routes

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/response"
)

// Deps bundles everything the router needs. Constructed in main.go.
type Deps struct {
	Auth                *handlers.AuthHandler
	MFA                 *handlers.MFAHandler
	JWT                 *jwt.JWTManager
	RateLimit           *middleware.RateLimiter
	DB                  *gorm.DB // optional, for /readyz
	MaxRequestBodyBytes int64    // §5 — global body-size cap applied BEFORE routes
}

// Register builds the full route tree and returns the configured engine.
// All endpoints live under /api/v1; auth endpoints under /api/v1/auth; MFA
// under /api/v1/auth/mfa — exactly per the prompt's structure.
func Register(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger())
	// §5 — global body-size limit. Applied here (before any route group) so it
	// covers every endpoint. Must be in Register, not after, because Gin
	// middlewares registered via Use apply only to routes defined afterwards.
	if deps.MaxRequestBodyBytes > 0 {
		r.Use(func(c *gin.Context) {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, deps.MaxRequestBodyBytes)
			c.Next()
		})
	}

	// health check — process liveness (no DB dependency).
	r.GET("/healthz", func(c *gin.Context) {
		response.Respond(c, 200, "ok", gin.H{"status": "ok"})
	})

	// readiness check — pings DB to confirm the app can serve requests (§7).
	r.GET("/readyz", func(c *gin.Context) {
		if deps.DB == nil {
			response.Respond(c, 200, "ok", gin.H{"status": "ok", "db": "skipped"})
			return
		}
		sqlDB, err := deps.DB.DB()
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
	})

	api := r.Group("/api/v1")
	auth := api.Group("/auth")

	// ---- Public core-auth endpoints (no auth middleware) ----
	auth.POST("/register", deps.RateLimit.Handler(), deps.Auth.Register)
	auth.POST("/login", deps.RateLimit.Handler(), deps.Auth.Login)
	auth.POST("/refresh-token", deps.Auth.Refresh)
	auth.POST("/forgot-password", deps.RateLimit.Handler(), deps.Auth.ForgotPassword)
	auth.POST("/reset-password", deps.Auth.ResetPassword)
	auth.POST("/verify-email", deps.Auth.VerifyEmail)

	// ---- Authenticated core-auth endpoints ----
	authed := auth.Group("")
	authed.Use(middleware.AuthMiddleware(deps.JWT))
	authed.POST("/logout", deps.Auth.Logout)
	authed.POST("/logout-all", deps.Auth.LogoutAll)
	authed.POST("/change-password", deps.Auth.ChangePassword)
	authed.GET("/me", deps.Auth.Me)

	// ---- MFA sub-group (authenticated) ----
	mfa := authed.Group("/mfa")
	mfa.POST("/send-otp", deps.RateLimit.Handler(), deps.MFA.SendOTP)
	mfa.POST("/verify-otp", deps.MFA.VerifyOTP)

	return r
}

// requestLogger is a minimal access log (§4 — token redaction). It logs
// method, path, status, latency, and request-ID but NEVER logs the
// Authorization header, refreshToken, token, password, or otp code fields.
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

		// Log after request completes — safe fields only.
		status := c.Writer.Status()
		latency := time.Since(start)
		log.Printf("[%s] %s %d %v rid=%s",
			c.Request.Method, c.Request.URL.Path,
			status, latency, requestID,
		)
	}
}

// generateRequestID creates a short pseudo-unique request identifier.
// In production this would use UUIDv4 or a snowflake ID.
func generateRequestID() string {
	const hex = "0123456789abcdef"
	b := make([]byte, 16)
	_ = b // placeholder — uses time-based for simplicity
	now := time.Now().UnixNano()
	for i := 0; i < 16; i++ {
		b[i] = hex[(now>>uint(i*4))&0xf]
		if i == 8 {
			now = time.Now().UnixNano() >> 32
		}
	}
	return string(b)
}
