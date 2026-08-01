// Command finnapigo-server boots the application: load config, connect DB,
// migrate, build the dependency graph (repos -> services -> handlers), and
// start the HTTP server.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/routes"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/utils"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("finnapigo: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	gin.SetMode(cfg.Server.GinMode)

	// --- Database ---
	db, err := database.Connect(cfg.DB)
	if err != nil {
		return err
	}
	log.Printf("database connected: %s:%s/%s", cfg.DB.Host, cfg.DB.Port, cfg.DB.Name)

	// --- Migrations (explicit; safe to run on every boot) ---
	if err := db.AutoMigrate(
		&models.User{}, &models.RefreshToken{}, &models.OtpCode{}, &models.AuditLog{},
	); err != nil {
		return errors.Join(errors.New("auto-migrate failed"), err)
	}

	// --- Dependency wiring (repositories -> services -> handlers) ---
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	otpRepo := repositories.NewOtpRepository(db)
	auditRepo := repositories.NewAuditRepository(db)

	jwtMgr := utils.NewJWTManager(cfg.JWT.Secret, cfg.JWT.Issuer)
	notifier := services.NewConsoleNotifier(cfg.SMTP.From)

	authSvc := services.NewAuthService(userRepo, tokenRepo, auditRepo, jwtMgr, cfg.Auth, cfg.JWT, notifier)
	mfaSvc := services.NewMFAService(otpRepo, userRepo, auditRepo, notifier, cfg.Auth)

	authHandler := handlers.NewAuthHandler(authSvc)
	mfaHandler := handlers.NewMFAHandler(mfaSvc)
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RPS, cfg.RateLimit.Burst)

	router := routes.Register(routes.Deps{
		Auth: authHandler, MFA: mfaHandler, JWT: jwtMgr, RateLimit: rateLimiter,
	})

	// --- HTTP server with graceful shutdown ---
	srv := &http.Server{
		Addr:              ":" + cfg.Server.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Run token/OTP cleanup in the background.
	go startCleanup(tokenRepo, otpRepo)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on :%s (mode=%s)", cfg.Server.Port, cfg.Server.GinMode)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Wait for interrupt or fatal error.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-stop:
		log.Println("shutdown signal received")
	case err := <-errCh:
		log.Printf("server error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return errors.Join(errors.New("graceful shutdown failed"), err)
	}
	log.Println("server stopped cleanly")
	return nil
}

// startCleanup periodically purges expired refresh tokens and OTP codes.
// Failures are logged but never fatal.
func startCleanup(tokenRepo *repositories.RefreshTokenRepository, otpRepo *repositories.OtpRepository) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		if n, err := tokenRepo.PurgeExpired(now); err == nil && n > 0 {
			log.Printf("cleanup: purged %d expired refresh tokens", n)
		}
		if n, err := otpRepo.PurgeExpired(now); err == nil && n > 0 {
			log.Printf("cleanup: purged %d expired/used OTPs", n)
		}
	}
}
