// Command finnapigo-server boots the application: load config, connect DB,
// migrate, build the dependency graph (repos -> services -> handlers), and
// start the HTTP server.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/metrics"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/routes"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
)

func main() {
	// Structured JSON logs for the whole process — every slog call (including
	// from libraries that use the default logger) emits machine-parseable JSON.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	if err := run(); err != nil {
		slog.Error("finnapigo fatal", "err", err)
		os.Exit(1)
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
	slog.Info("database connected", "host", cfg.DB.Host, "port", cfg.DB.Port, "db", cfg.DB.Name)

	// --- Migrations (explicit; safe to run on every boot) ---
	if err := db.AutoMigrate(
		&models.User{}, &models.RefreshToken{},
		&models.AuditLog{}, &models.UsedToken{}, &models.TOTPDevice{}, &models.RecoveryCode{},
		&models.OAuthIdentity{},
	); err != nil {
		return errors.Join(errors.New("auto-migrate failed"), err)
	}

	// --- Repositories ---
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	baseAuditRepo := repositories.NewAuditRepository(db)
	// auditRepo buffers audit writes on a background worker; it is closed
	// explicitly in the shutdown sequence (NOT deferred) so the flush is
	// ordered before the DB pool close. Boot-failure returns below bypass the
	// flush, but those paths have served no traffic yet.
	auditRepo := services.NewAsyncAuditWriter(baseAuditRepo, baseAuditRepo, cfg.Audit)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	oauthIdentityRepo := repositories.NewOAuthIdentityRepository(db)

	// --- Store (in-memory default; Redis when REDIS_URL set) ---
	// §1.3/§7 — rate-limit counters, velocity windows, and jti tracking are
	// shared across instances when Redis is configured; otherwise in-memory.
	var kvStore store.Store
	if cfg.Redis.URL != "" {
		redisStore, closeRedis, err := store.NewRedisStoreFromURL(cfg.Redis.URL)
		if err != nil {
			return fmt.Errorf("store: connect redis: %w", err)
		}
		defer func() { _ = closeRedis() }()
		kvStore = redisStore
		slog.Info("store: Redis-backed (shared across instances)")
	} else {
		memStore := store.NewInMemoryStore(5 * time.Minute)
		defer memStore.Close()
		kvStore = memStore
		slog.Info("store: in-memory (single-instance mode)")
	}

	// --- JWT ---
	jwtMgr := jwt.NewJWTManager(cfg.JWT.Secret, cfg.JWT.Issuer)

	// --- Notifier (§1.2: SMTP when configured, Console fallback) ---
	smtpNotif := services.NewSMTPNotifier(cfg.SMTP.Host, cfg.SMTP.Port,
		cfg.SMTP.User, cfg.SMTP.Password, cfg.SMTP.From)
	var notifier services.Notifier
	if smtpNotif.Enabled() {
		notifier = smtpNotif
		slog.Info("email: SMTP notifier enabled")
	} else {
		notifier = services.NewConsoleNotifier(cfg.SMTP.From)
		slog.Warn("email: SMTP_HOST not set — using console notifier (tokens logged to stdout)")
	}

	// --- CAPTCHA verifier (§2: off by default) ---
	var captchaVerifier services.CaptchaVerifier // nil = NoOp in handler
	if cfg.Captcha.Provider == "turnstile" {
		if cfg.Captcha.Secret == "" {
			slog.Warn("captcha: CAPTCHA_PROVIDER=turnstile but CAPTCHA_SECRET is empty — CAPTCHA disabled")
		} else {
			captchaVerifier = services.NewTurnstileVerifier(cfg.Captcha.Secret)
			slog.Info("captcha: Turnstile verifier enabled")
		}
	}

	// --- Services ---
	// recoveryEncKey seals the re-viewable copy of each MFA recovery code
	// (AES-256-GCM). RECOVERY_CODE_KEY (hex, 32 bytes) wins when set; otherwise
	// the key is domain-separated-derived from JWT_SECRET so deployments
	// without the extra variable still work. Rotating JWT_SECRET (or the key)
	// orphans previously sealed codes — users regenerate a fresh set.
	recoveryEncKey, err := recoveryEncryptionKey(cfg)
	if err != nil {
		return err
	}
	// Build the AES-256-GCM cipher ONCE — the key never changes at runtime, so
	// the key schedule is computed here instead of per Encrypt/Decrypt call.
	recoveryEnc, err := crypto.NewEncryptor(recoveryEncKey)
	if err != nil {
		return fmt.Errorf("recovery-code encryptor: %w", err)
	}
	totpSvc := services.NewTOTPService(totpRepo, kvStore, auditRepo, cfg.JWT.Issuer, cfg.Auth, recoveryEnc, jwtMgr)
	authSvc := services.NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditRepo, kvStore,
		jwtMgr, cfg.Auth, cfg.RateLimit, cfg.JWT, notifier, captchaVerifier, nil,
		totpRepo, totpSvc,
	)

	// --- Google OAuth (endpoints only registered when fully configured) ---
	var oauthHandler *handlers.OAuthHandler
	if gClient := services.NewGoogleOAuthClient(cfg.GoogleOAuth.ClientID, cfg.GoogleOAuth.ClientSecret, cfg.GoogleOAuth.RedirectURL); gClient != nil {
		gVerifier := services.NewProductionGoogleVerifier(cfg.GoogleOAuth.ClientID)
		oauthSvc := services.NewOAuthService(userRepo, oauthIdentityRepo, kvStore, authSvc, gVerifier, gClient)
		oauthHandler = handlers.NewOAuthHandler(oauthSvc)
		slog.Info("oauth: Google sign-in enabled")
	} else {
		slog.Info("oauth: GOOGLE_CLIENT_ID / GOOGLE_REDIRECT_URL not set — Google sign-in disabled")
	}

	// --- Handlers ---
	authHandler := handlers.NewAuthHandler(authSvc, captchaVerifier)
	mfaHandler := handlers.NewMFAHandler(totpSvc, jwtMgr, cfg.JWT.SudoTTL)
	sessionHandler := handlers.NewSessionHandler(authSvc)

	// --- Rate limiter ---
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RPS, cfg.RateLimit.Burst, cfg.Security.RateLimiterEntryTTL, kvStore)
	defer rateLimiter.Close()

	// --- TOTP concurrency limiter (caps CPU-bound validations) ---
	totpCluster := middleware.NewConcurrencyLimiter(cfg.Security.TOTPMaxConcurrent)

	// --- Router ---
	router := routes.Register(routes.Deps{
		Auth:                authHandler,
		OAuth:               oauthHandler,
		MFA:                 mfaHandler,
		Sessions:            sessionHandler,
		JWT:                 jwtMgr,
		RateLimit:           rateLimiter,
		TOTPCluster:         totpCluster,
		DB:                  db,
		MaxRequestBodyBytes: cfg.Security.MaxRequestBodyBytes,
		TrustedProxies:      cfg.Server.TrustedProxies,
		HSTSSeconds:         cfg.Server.HSTSSeconds,
		PwdVersion:          authSvc.CurrentPwdVersion,
		Metrics:             metrics.Handler(func() float64 { return float64(auditRepo.Buffered()) }),
	})

	// --- HTTP server with graceful shutdown ---
	srv := &http.Server{
		Addr:              ":" + cfg.Server.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Run token/used-token cleanup in the background.
	go startCleanup(tokenRepo, usedTokenRepo)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("server listening", "port", cfg.Server.Port, "mode", cfg.Server.GinMode)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Wait for interrupt or fatal error.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-stop:
		slog.Info("shutdown signal received")
	case err := <-errCh:
		slog.Error("server error", "err", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(ctx)

	// Flush resources in dependency order: the async audit writer drains its
	// buffer into the DB first, then the DB pool itself is closed. Closing in
	// the reverse order would drop buffered audit rows.
	slog.Info("flushing resources")
	auditRepo.Close()
	if sqlDB, derr := db.DB(); derr == nil {
		_ = sqlDB.Close()
	}

	if err != nil {
		return errors.Join(errors.New("graceful shutdown failed"), err)
	}
	slog.Info("server stopped cleanly")
	return nil
}

// recoveryEncryptionKey resolves the AES-256 key that seals the re-viewable
// copy of MFA recovery codes: RECOVERY_CODE_KEY (64-char hex) when provided,
// otherwise a domain-separated SHA-256 derivation of JWT_SECRET. The fallback
// keeps deployments without the extra variable working; a dedicated key is
// still preferred so the two secrets rotate independently. Rotating either
// orphans previously sealed codes — affected users regenerate a fresh set.
func recoveryEncryptionKey(cfg *config.Config) ([]byte, error) {
	if cfg.Auth.RecoveryCodeKey != "" {
		key, err := hex.DecodeString(cfg.Auth.RecoveryCodeKey)
		if err != nil || len(key) != crypto.KeyLen {
			return nil, errors.New("RECOVERY_CODE_KEY must be 64 hex chars (32 bytes)")
		}
		return key, nil
	}
	if cfg.JWT.Secret == "" {
		return nil, errors.New("cannot derive recovery-code key: JWT_SECRET is empty")
	}
	slog.Warn("recovery codes: RECOVERY_CODE_KEY not set — deriving key from JWT_SECRET (configure a dedicated key for production)")
	sum := sha256.Sum256([]byte(cfg.JWT.Secret + ":finnapigo:recovery-codes:v1"))
	return sum[:], nil
}

// startCleanup periodically purges expired refresh tokens and used-token
// rows. Failures are logged but never fatal.
func startCleanup(
	tokenRepo *repositories.RefreshTokenRepository,
	usedTokenRepo *repositories.UsedTokenRepository,
) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	ctx := context.Background()
	for range ticker.C {
		now := time.Now()
		if n, err := tokenRepo.PurgeExpired(ctx, now); err == nil && n > 0 {
			slog.Info("cleanup: purged expired refresh tokens", "count", n)
		}
		if n, err := usedTokenRepo.PurgeExpired(ctx, now); err == nil && n > 0 {
			slog.Info("cleanup: purged expired used tokens", "count", n)
		}
	}
}
