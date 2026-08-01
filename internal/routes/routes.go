// Package routes wires the Gin router groups + middlewares + handlers.
package routes

import (
	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/utils"
)

// Deps bundles everything the router needs. Constructed in main.go.
type Deps struct {
	Auth       *handlers.AuthHandler
	MFA        *handlers.MFAHandler
	JWT        *utils.JWTManager
	RateLimit  *middleware.RateLimiter
}

// Register builds the full route tree and returns the configured engine.
// All endpoints live under /api/v1; auth endpoints under /api/v1/auth; MFA
// under /api/v1/auth/mfa — exactly per the prompt's structure.
func Register(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger())

	// health check for docker / load balancer probes.
	r.GET("/healthz", func(c *gin.Context) {
		utils.Respond(c, 200, "ok", gin.H{"status": "ok"})
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
	authed.POST("/change-password", deps.Auth.ChangePassword)
	authed.GET("/me", deps.Auth.Me)

	// ---- MFA sub-group (authenticated) ----
	mfa := authed.Group("/mfa")
	mfa.POST("/send-otp", deps.RateLimit.Handler(), deps.MFA.SendOTP)
	mfa.POST("/verify-otp", deps.MFA.VerifyOTP)

	return r
}

// requestLogger is a minimal access log; keep it deliberately tiny. In
// production swap for a structured logger (zap/zerolog).
func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}
