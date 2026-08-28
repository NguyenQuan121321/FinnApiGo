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
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jobs"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/logging"
	"github.com/finnapigo/finnapigo/internal/metrics"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/routes"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tracing"
)

func main() {
	// Structured JSON logs for the whole process — every slog call (including
	// from libraries that use the default logger) emits machine-parseable JSON.
	// The redacting handler (G2) guarantees secret-shaped attributes never
	// reach stdout, regardless of call-site discipline.
	slog.SetDefault(slog.New(logging.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))))
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

	// O1 — distributed tracing: no-op provider (and zero export overhead)
	// unless OTEL_EXPORTER_OTLP_ENDPOINT is set. Flushed at shutdown.
	setupTracing, err := tracing.Setup(context.Background())
	if err != nil {
		return err
	}
	defer func() { _ = setupTracing(context.Background()) }()

	// G1 — release mode must acknowledge the audit PII retention policy.
	if msg := auditRetentionWarning(cfg); msg != "" {
		slog.Warn(msg)
	}
	// X1 — release mode must acknowledge the metrics exposure policy.
	if cfg.Server.MetricsAddr == "" && cfg.Server.GinMode == gin.ReleaseMode {
		slog.Warn("metrics: METRICS_ADDR is unset in release mode — /metrics is served on the PUBLIC listener; set METRICS_ADDR to an internal address (e.g. 127.0.0.1:9090)")
	}

	// --- Database ---
	db, err := database.Connect(cfg.DB)
	if err != nil {
		return err
	}
	slog.Info("database connected", "host", cfg.DB.Host, "port", cfg.DB.Port, "db", cfg.DB.Name)

	// --- Schema (R1) ---
	// Production NEVER auto-migrates at boot: schema changes ship as
	// golang-migrate files (migrations/, applied by `go run ./cmd/migrate
	// up` as a deploy step). MIGRATE_AUTO=true re-enables GORM AutoMigrate
	// as the dev-only escape hatch.
	if cfg.DB.MigrateAuto {
		slog.Warn("MIGRATE_AUTO=true — running GORM AutoMigrate at boot (dev escape hatch; production must use cmd/migrate)")
		if err := db.AutoMigrate(
			&models.User{}, &models.RefreshToken{},
			&models.AuditLog{}, &models.UsedToken{}, &models.TOTPDevice{}, &models.RecoveryCode{},
			&models.OAuthIdentity{}, &models.PasskeyCredential{},
		); err != nil {
			return errors.Join(errors.New("auto-migrate failed"), err)
		}
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

	// --- JWT (K2: versioned keyset when JWT_SECRET_PREVIOUS is set) ---
	jwtMgr := jwt.NewRotatingJWTManager(cfg.JWT.Secret, cfg.JWT.PreviousSecret, cfg.JWT.Issuer)
	if cfg.JWT.PreviousSecret != "" && cfg.JWT.PreviousSecret != cfg.JWT.Secret {
		slog.Info("jwt: rotation active — current + previous secrets accepted until legacy tokens expire")
	}

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

	// --- Passkeys / WebAuthn (Phase 9) — enabled only when RP configured ---
	var passkeyHandler *handlers.PasskeyHandler
	if cfg.WebAuthn.RPID != "" {
		passkeySvc, err := services.NewPasskeyService(
			repositories.NewPasskeyRepository(db), userRepo, auditRepo, kvStore,
			authSvc, services.PasskeyConfig{
				RPDisplayName:         cfg.WebAuthn.RPDisplayName,
				RPID:                  cfg.WebAuthn.RPID,
				RPOrigins:             cfg.WebAuthn.RPOrigins,
				AttestationPreference: cfg.WebAuthn.AttestationPreference,
			},
		)
		if err != nil {
			return fmt.Errorf("passkey: %w", err)
		}
		passkeyHandler = handlers.NewPasskeyHandler(passkeySvc)
		slog.Info("passkey: WebAuthn enabled", "rp_id", cfg.WebAuthn.RPID)
	} else {
		slog.Info("passkey: WEBAUTHN_RP_ID not set — passkey endpoints disabled")
	}

	// --- Handlers ---
	authHandler := handlers.NewAuthHandler(authSvc, captchaVerifier)
	mfaHandler := handlers.NewMFAHandler(totpSvc, jwtMgr, cfg.JWT.SudoTTL)
	sessionHandler := handlers.NewSessionHandler(authSvc)

	// --- Rate limiter ---
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RPS, cfg.RateLimit.Burst, cfg.Security.RateLimiterEntryTTL, kvStore)
	defer rateLimiter.Close()

	// --- Internal-only endpoints (X1/X2): metrics + pprof off the public API ---
	metricsH := metrics.Handler(func() float64 { return float64(auditRepo.Buffered()) })
	// X1 — when METRICS_ADDR is set, metrics leave the public router and are
	// served on the dedicated internal listener below.
	publicMetricsHandler := metricsH
	if cfg.Server.MetricsAddr != "" {
		publicMetricsHandler = nil
	}
	defer startInternalServers(cfg.Server.MetricsAddr, cfg.Server.PProfAddr, cfg.Server.MetricsToken, metricsH)()

	// --- TOTP concurrency limiter (caps CPU-bound validations) ---
	totpCluster := middleware.NewConcurrencyLimiter(cfg.Security.TOTPMaxConcurrent)

	// --- Router ---
	router := routes.Register(routes.Deps{
		Auth:                authHandler,
		OAuth:               oauthHandler,
		MFA:                 mfaHandler,
		Sessions:            sessionHandler,
		Passkey:             passkeyHandler,
		JWT:                 jwtMgr,
		RateLimit:           rateLimiter,
		TOTPCluster:         totpCluster,
		DB:                  db,
		MaxRequestBodyBytes: cfg.Security.MaxRequestBodyBytes,
		TrustedProxies:      cfg.Server.TrustedProxies,
		HSTSSeconds:         cfg.Server.HSTSSeconds,
		PwdVersion:          authSvc.CurrentPwdVersion,
		Metrics:             publicMetricsHandler,
		Tracing:             true,
		CORSAllowedOrigins:  cfg.Server.CORSAllowedOrigins,
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

	// Run token/used-token/audit-retention cleanup in the background (S2):
	// leader-elected via the shared store by default (exactly one replica
	// runs it), with the RUN_JOBS tri-state as the explicit override.
	stopJobs := startJobs(cfg, tokenRepo, usedTokenRepo, baseAuditRepo, kvStore)
	defer stopJobs()

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
// copy of MFA recovery codes (K1/K3): KEY_PROVIDER=file reads
// <KEY_DIR>/recovery_codes.key; otherwise RECOVERY_CODE_KEY (64-char hex)
// wins. Without either, release mode refuses to boot — silently deriving the
// key from JWT_SECRET couples the two secrets: one leaked secret unravels
// both token integrity and recovery-code confidentiality. Dev mode keeps the
// derivation with a loud warning so local setups stay zero-config. Rotating
// the key orphans previously sealed codes — users regenerate a fresh set.
func recoveryEncryptionKey(cfg *config.Config) ([]byte, error) {
	if cfg.Security.KeyProvider == "file" {
		return crypto.NewFileKeyProvider(cfg.Security.KeyDir).Retrieve(crypto.KeyNameRecoveryCodes)
	}
	if cfg.Auth.RecoveryCodeKey != "" {
		key, err := hex.DecodeString(cfg.Auth.RecoveryCodeKey)
		if err != nil || len(key) != crypto.KeyLen {
			return nil, errors.New("RECOVERY_CODE_KEY must be 64 hex chars (32 bytes)")
		}
		return key, nil
	}
	if cfg.Server.GinMode == gin.ReleaseMode {
		return nil, errors.New("RECOVERY_CODE_KEY is required in release mode (set a dedicated 64-hex-char AES-256 key; deriving it from JWT_SECRET is disabled)")
	}
	if cfg.JWT.Secret == "" {
		return nil, errors.New("cannot derive recovery-code key: JWT_SECRET is empty")
	}
	slog.Warn("recovery codes: RECOVERY_CODE_KEY not set — deriving key from JWT_SECRET (dev only; release mode refuses to boot without it)")
	sum := sha256.Sum256([]byte(cfg.JWT.Secret + ":finnapigo:recovery-codes:v1"))
	return sum[:], nil
}

// auditRetentionWarning implements the G1 policy decision: retention is a
// release-mode WARNING, not a boot failure. Retention is a data-governance
// CHOICE (some deployments are contractually required to keep history), so
// refusing to boot would force that choice under rollout pressure; instead
// the operator gets an explicit, loud notice that audit rows — which carry
// PII (email, IP) — are being kept forever. Dev mode stays silent.
func auditRetentionWarning(cfg *config.Config) string {
	if cfg.Server.GinMode != gin.ReleaseMode || cfg.Audit.RetentionDays > 0 {
		return ""
	}
	return "audit retention: AUDIT_RETENTION_DAYS is unset in release mode — audit rows (PII: email, IP) are kept forever; set a retention window (see README PII/retention policy)"
}

// startJobs runs the token/used-token/audit-retention purge on a cadence
// under the S2 policy: leader election via the shared store by default (a
// single instance is always its own leader), RUN_JOBS=true to run
// unconditionally on this replica, RUN_JOBS=false to disable here. Returns
// the stop function for graceful shutdown.
func startJobs(
	cfg *config.Config,
	tokenRepo *repositories.RefreshTokenRepository,
	usedTokenRepo *repositories.UsedTokenRepository,
	auditRepo *repositories.AuditRepository,
	kv store.Store,
) (stop func()) {
	const (
		interval = 5 * time.Minute
		lockTTL  = 15 * time.Minute // >= 2x interval: the claim outlives a missed tick
	)
	runOnce := func(ctx context.Context) {
		now := time.Now()
		if n, err := tokenRepo.PurgeExpired(ctx, now); err == nil && n > 0 {
			slog.Info("cleanup: purged expired refresh tokens", "count", n)
		}
		if n, err := usedTokenRepo.PurgeExpired(ctx, now); err == nil && n > 0 {
			slog.Info("cleanup: purged expired used tokens", "count", n)
		}
		if cfg.Audit.RetentionDays > 0 {
			cutoff := now.AddDate(0, 0, -cfg.Audit.RetentionDays)
			if n, err := auditRepo.PurgeOlderThan(ctx, cutoff); err == nil && n > 0 {
				slog.Info("cleanup: purged audit rows past retention", "days", cfg.Audit.RetentionDays, "count", n)
			} else if err != nil {
				slog.Error("cleanup: audit retention purge failed", "err", err)
			}
		}
	}
	switch {
	case cfg.Server.RunJobs != nil && *cfg.Server.RunJobs:
		slog.Warn("jobs: RUN_JOBS=true — background jobs run unconditionally on this replica (pin to exactly ONE replica)")
		ctx, cancel := context.WithCancel(context.Background())
		go jobs.RunWhileLeader(ctx, interval, runOnce)
		return cancel
	case cfg.Server.RunJobs != nil && !*cfg.Server.RunJobs:
		slog.Info("jobs: RUN_JOBS=false — background jobs disabled on this replica")
		return func() {}
	default:
		runner := jobs.NewLeaderRunner(kv, "cleanup", interval, lockTTL, runOnce)
		runner.Start()
		slog.Info("jobs: leader-elected background jobs active", "lock", "jobs:leader:cleanup", "interval", interval.String())
		return runner.Stop
	}
}

// startInternalServers binds the internal-only endpoints (X1/X2) on private
// listeners that are never part of the public API engine:
//
//   - METRICS_ADDR → Prometheus /metrics (optionally Bearer-gated by
//     METRICS_TOKEN). Empty = metrics stay on the public router (legacy dev
//     behavior; warned about in release mode — see run()).
//   - PPROF_ADDR → net/http/pprof under /debug/pprof/ (P3). Empty = disabled.
//   - Both set to the SAME address → ONE internal server mounts both.
//
// Each listener uses a private mux and a bounded header timeout (G112).
func startInternalServers(metricsAddr, pprofAddr, metricsToken string, metricsH http.Handler) (stopAll func()) {
	var shutdowns []func()
	mountPProf := func(mux *http.ServeMux) {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	startListener := func(name, addr string, mux *http.ServeMux) func() {
		srv := &http.Server{
			Addr: addr, Handler: mux,
			ReadHeaderTimeout: 5 * time.Second, // gosec G112 — bound slow clients
		}
		go func() {
			slog.Info("internal server listening", "name", name, "addr", addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("internal server failed", "name", name, "addr", addr, "err", err)
			}
		}()
		return func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}
	}
	switch {
	case metricsAddr != "" && metricsAddr == pprofAddr:
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.BearerAuth(metricsToken, metricsH))
		mountPProf(mux)
		shutdowns = append(shutdowns, startListener("internal", metricsAddr, mux))
	case metricsAddr != "":
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.BearerAuth(metricsToken, metricsH))
		shutdowns = append(shutdowns, startListener("metrics", metricsAddr, mux))
		if pprofAddr != "" {
			pprofMux := http.NewServeMux()
			mountPProf(pprofMux)
			shutdowns = append(shutdowns, startListener("pprof", pprofAddr, pprofMux))
		}
	case pprofAddr != "":
		mux := http.NewServeMux()
		mountPProf(mux)
		shutdowns = append(shutdowns, startListener("pprof", pprofAddr, mux))
	}
	return func() {
		for _, s := range shutdowns {
			s()
		}
	}
}
