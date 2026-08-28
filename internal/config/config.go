// Package config loads configuration from environment variables (.env supported).
// No hardcoded secrets or lifetimes anywhere in the codebase — everything is read here.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds every runtime knob for the application.
type Config struct {
	Server      ServerConfig
	DB          DBConfig
	JWT         JWTConfig
	Auth        AuthConfig
	RateLimit   RateLimitConfig
	SMTP        SMTPConfig
	Redis       RedisConfig
	Security    SecurityConfig
	Captcha     CaptchaConfig
	GoogleOAuth GoogleOAuthConfig
	Audit       AuditConfig
}

type ServerConfig struct {
	Port    string
	GinMode string
	// TrustedProxies is the comma-separated list (TRUSTED_PROXIES) of CIDR/IPs
	// that may set X-Forwarded-For / X-Real-IP. Empty (default) trusts NO proxy,
	// so c.ClientIP() returns the direct RemoteAddr — the spoof-proof default.
	// Set this to your load balancer / Cloudflare / Nginx egress CIDRs in
	// production so the app resolves the real client IP for session metadata.
	TrustedProxies []string
	// PProfAddr (env PPROF_ADDR) starts a net/http/pprof listener on this
	// address when non-empty (P3). Empty (default) = disabled. Bind to an
	// internal address — pprof must never be publicly reachable.
	PProfAddr string
	// HSTSSeconds (env HSTS_SECONDS) enables the Strict-Transport-Security
	// header on HTTPS responses when > 0 (A3). 0 (default) sends no HSTS —
	// correct for plain-HTTP dev setups behind no TLS terminator.
	HSTSSeconds int
	// RunJobs (env RUN_JOBS) controls background jobs (S2). Unset (nil,
	// default) = leader election via the shared store — exactly one replica
	// runs cleanup; single-instance deployments are always their own leader.
	// true = this replica runs jobs unconditionally (the minimal variant:
	// pin it to exactly one replica). false = jobs disabled on this replica.
	RunJobs *bool
}

type DBConfig struct {
	Host         string
	Port         string
	User         string
	Password     string
	Name         string
	MaxIdleConns int
	MaxOpenConns int
	// TLS appends ?tls=... to the DSN: "true" (verify CA + hostname),
	// "skip-verify", "preferred", or "" (disabled — plaintext, local dev only).
	TLS string
	// MigrateAuto (env MIGRATE_AUTO) re-enables GORM AutoMigrate at boot —
	// the DEV-ONLY escape hatch (R1). Production defaults to false: schema
	// changes go through the golang-migrate files applied by cmd/migrate as
	// a deploy step.
	MigrateAuto bool
}

// DSN builds a MySQL DSN string for GORM.
func (d DBConfig) DSN() string {
	// charset=utf8mb4 to fully support emoji / 4-byte UTF-8. loc=UTC (R3):
	// with parseTime=True the driver converts DATETIME values to time.Time in
	// this location, so every DB round-trip normalizes to UTC regardless of
	// the host's local timezone (parseTime paths audited: this DSN is the only
	// one in the codebase; internal/database consumes it verbatim).
	dsn := d.User + ":" + d.Password + "@tcp(" + d.Host + ":" + d.Port + ")/" +
		d.Name + "?charset=utf8mb4&parseTime=True&loc=UTC"
	if d.TLS != "" {
		dsn += "&tls=" + d.TLS
	}
	return dsn
}

type JWTConfig struct {
	Secret string
	// PreviousSecret (env JWT_SECRET_PREVIOUS) optionally holds the prior
	// JWT secret during a rotation (K2): new tokens are signed with Secret,
	// while tokens carrying the previous kid keep verifying until they
	// expire. Empty = single-key mode.
	PreviousSecret string
	Issuer         string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	ResetTTL      time.Duration
	VerifyTTL     time.Duration
	MFAPendingTTL time.Duration
	// SudoTTL is the lifetime of the short-lived "sudo" token minted after a
	// successful TOTP verification on the recovery-codes view endpoint.
	// Within this window the user may regenerate codes without re-entering
	// a TOTP code (GitHub-style sudo mode).
	SudoTTL time.Duration
}

type AuthConfig struct {
	MaxLoginAttempts     int
	LoginLockoutDuration time.Duration
	// MaxLockoutMultiplier caps the exponential backoff applied to repeat
	// offenders (§3). E.g. base 15m * min(lockoutCount, MaxLockoutMultiplier).
	MaxLockoutMultiplier int
	// RequireEmailVerified gates sensitive actions behind is_email_verified
	// (§2). When true, login is still allowed (UX) but document it as a policy.
	RequireEmailVerified bool
	// ---- TOTP brute-force protection ----
	// TOTPMaxAttempts is the maximum failed validate/verify attempts allowed
	// per user within TOTPAttemptWindow before the account is locked out of
	// MFA (returns 429). Backstops the per-IP rate limiter: even if an attacker
	// rotates IPs, repeated wrong codes against one account are throttled.
	TOTPMaxAttempts int
	// TOTPAttemptWindow is the sliding window over which TOTPMaxAttempts counts.
	TOTPAttemptWindow time.Duration
	// RecoveryCodeCount is how many one-time recovery codes are issued.
	RecoveryCodeCount int
	// RecoveryCodeBytes is the entropy (in bytes) of each recovery code before
	// hex encoding (16 => 128-bit codes, 32 hex chars).
	RecoveryCodeBytes int
	// RecoveryCodeKey is an optional hex-encoded 32-byte AES-256 key used to
	// seal the re-viewable copy of each recovery code. When empty the key is
	// derived from JWT_SECRET (see cmd/server wiring).
	RecoveryCodeKey string
}

type RateLimitConfig struct {
	RPS   float64
	Burst int
	// Per-account login limiter (§3): max attempts per email per window.
	LoginPerAccountMax int
	LoginWindow        time.Duration
	// Registration velocity (§2): max registrations per IP/subnet per hour.
	RegisterPerIPMax int
	RegisterWindow   time.Duration
	// Verify-email resend limiter per email (§3): stops an attacker
	// email-bombing one inbox by rotating IPs.
	VerifyResendPerEmailMax int
	VerifyResendWindow      time.Duration
	// Global resend volume cap (§7.6.3 anti-automation): hard circuit-breaker on
	// total resends across ALL emails+IPs. Stops industrial-scale flooding that
	// defeats per-key limits (botnet rotating both IPs and emails). Shared
	// across instances via the store.
	VerifyResendGlobalMax    int
	VerifyResendGlobalWindow time.Duration
	// Per-IP service-layer resend throttle (§7.6.3): store-backed so it is
	// shared across instances, unlike the in-process middleware limiter.
	VerifyResendPerIPMax    int
	VerifyResendPerIPWindow time.Duration
	// After this many failed logins from one IP, require a CAPTCHA (§3).
	LoginCaptchaAfterFails int
}

type SMTPConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
}

// RedisConfig is optional. When URL is empty the app uses an in-process
// InMemoryStore; when set, a Redis-backed Store is used so rate limits and
// single-use token state are shared across instances (§7).
type RedisConfig struct {
	URL string
}

// SecurityConfig holds cross-cutting hardening knobs.
type SecurityConfig struct {
	// MaxRequestBodyBytes caps every request body (§5) to prevent large-payload DoS.
	MaxRequestBodyBytes int64
	// MaxPasswordLength is retained for deployment compatibility. Password
	// validation enforces bcrypt's 72-byte hard limit in the service layer.
	MaxPasswordLength int
	// RateLimiterEntryTTL bounds the per-IP rate-limiter map (§1.3).
	RateLimiterEntryTTL time.Duration
	// TOTPMaxConcurrent caps the number of concurrent CPU-bound TOTP
	// validations (Enable/VerifyEnable/Validate). Excess requests are rejected
	// with 429 immediately, so a flood of validations cannot starve worker
	// threads. 0 disables the gate (keeps legacy behavior for tests).
	TOTPMaxConcurrent int
}

// CaptchaConfig drives the optional CAPTCHA on /register and post-fail /login.
// Secret empty => CAPTCHA disabled (NoOpVerifier). Provider selects the vendor.
type CaptchaConfig struct {
	Provider string // "turnstile" | "hcaptcha" | "" (= off)
	Secret   string
	SiteKey  string
}

// GoogleOAuthConfig holds the credentials and redirect URL for Google
// OAuth 2.0 / OpenID Connect sign-in. When ClientID is empty the feature
// is disabled and the /auth/google/* endpoints return 501.
type GoogleOAuthConfig struct {
	ClientID     string // GOOGLE_CLIENT_ID
	ClientSecret string // GOOGLE_CLIENT_SECRET
	RedirectURL  string // GOOGLE_REDIRECT_URL
}

// AuditConfig drives async audit logging (§7).
type AuditConfig struct {
	// BufferSize is the channel capacity; on overflow entries are dropped
	// (never block a request). 0 => synchronous fallback.
	BufferSize int
	// FlushBatch is how many rows the worker inserts per DB round-trip.
	FlushBatch int
	// RetentionDays caps how long audit rows are kept (env
	// AUDIT_RETENTION_DAYS): the cleanup job batch-deletes older rows. 0
	// (default) keeps audit history forever. Audit rows contain PII (email,
	// IP) — see the README retention note before enabling.
	RetentionDays int
}

// Load reads .env (if present) and environment variables, applying sane defaults
// only for non-secret values. JWT secret has NO default — it must be set.
func Load() (*Config, error) {
	// .env is optional in production (env may be injected directly).
	_ = godotenv.Load()

	l := &loader{}
	cfg := &Config{
		Server: ServerConfig{
			Port:           l.env("SERVER_PORT", "8080"),
			GinMode:        l.env("GIN_MODE", "debug"),
			TrustedProxies: l.envCSV("TRUSTED_PROXIES"),
			PProfAddr:      l.env("PPROF_ADDR", ""),
			HSTSSeconds:    l.envInt("HSTS_SECONDS", 0),
			RunJobs:        l.envOptionalBool("RUN_JOBS"),
		},
		DB: DBConfig{
			Host:         l.env("DB_HOST", "127.0.0.1"),
			Port:         l.env("DB_PORT", "3306"),
			User:         l.env("DB_USER", "finnapigo"),
			Password:     l.env("DB_PASSWORD", ""),
			Name:         l.env("DB_NAME", "finnapigo"),
			MaxIdleConns: l.envInt("DB_MAX_IDLE_CONNS", 10),
			MaxOpenConns: l.envInt("DB_MAX_OPEN_CONNS", 100),
			TLS:          l.env("DB_TLS", ""),
			MigrateAuto:  l.envBool("MIGRATE_AUTO", false),
		},
		JWT: JWTConfig{
			Secret:         l.env("JWT_SECRET", ""),
			PreviousSecret: l.env("JWT_SECRET_PREVIOUS", ""),
			Issuer:         l.env("JWT_ISSUER", "finnapigo"),
			AccessTTL:     l.envDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTTL:    l.envDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
			ResetTTL:      l.envDuration("RESET_TOKEN_TTL", 15*time.Minute),
			VerifyTTL:     l.envDuration("EMAIL_VERIFY_TOKEN_TTL", 24*time.Hour),
			MFAPendingTTL: l.envDuration("MFA_PENDING_TOKEN_TTL", 5*time.Minute),
			SudoTTL:       l.envDuration("SUDO_TOKEN_TTL", 15*time.Minute),
		},
		Auth: AuthConfig{
			MaxLoginAttempts:     l.envInt("MAX_LOGIN_ATTEMPTS", 5),
			LoginLockoutDuration: l.envDuration("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
			MaxLockoutMultiplier: l.envInt("MAX_LOCKOUT_MULTIPLIER", 4),
			RequireEmailVerified: l.envBool("REQUIRE_EMAIL_VERIFIED", false),
			TOTPMaxAttempts:      l.envInt("TOTP_MAX_ATTEMPTS", 5),
			TOTPAttemptWindow:    l.envDuration("TOTP_ATTEMPT_WINDOW", 5*time.Minute),
			RecoveryCodeCount:    l.envInt("RECOVERY_CODE_COUNT", 10),
			RecoveryCodeBytes:    l.envInt("RECOVERY_CODE_BYTES", 16),
			RecoveryCodeKey:      l.env("RECOVERY_CODE_KEY", ""),
		},
		RateLimit: RateLimitConfig{
			RPS:                      l.envFloat("RATE_LIMIT_RPS", 5),
			Burst:                    l.envInt("RATE_LIMIT_BURST", 10),
			LoginPerAccountMax:       l.envInt("LOGIN_PER_ACCOUNT_MAX", 10),
			LoginWindow:              l.envDuration("LOGIN_WINDOW", 1*time.Minute),
			RegisterPerIPMax:         l.envInt("REGISTER_PER_IP_MAX", 5),
			RegisterWindow:           l.envDuration("REGISTER_WINDOW", 1*time.Hour),
			VerifyResendPerEmailMax:  l.envInt("VERIFY_RESEND_PER_EMAIL_MAX", 3),
			VerifyResendWindow:       l.envDuration("VERIFY_RESEND_WINDOW", 1*time.Hour),
			VerifyResendGlobalMax:    l.envInt("VERIFY_RESEND_GLOBAL_MAX", 100),
			VerifyResendGlobalWindow: l.envDuration("VERIFY_RESEND_GLOBAL_WINDOW", 1*time.Hour),
			VerifyResendPerIPMax:     l.envInt("VERIFY_RESEND_PER_IP_MAX", 5),
			VerifyResendPerIPWindow:  l.envDuration("VERIFY_RESEND_PER_IP_WINDOW", 1*time.Hour),
			LoginCaptchaAfterFails:   l.envInt("LOGIN_CAPTCHA_AFTER_FAILS", 5),
		},
		SMTP: SMTPConfig{
			Host:     l.env("SMTP_HOST", ""),
			Port:     l.env("SMTP_PORT", "587"),
			User:     l.env("SMTP_USER", ""),
			Password: l.env("SMTP_PASSWORD", ""),
			From:     l.env("SMTP_FROM", "no-reply@finnapigo.local"),
		},
		Redis: RedisConfig{
			URL: l.env("REDIS_URL", ""),
		},
		Security: SecurityConfig{
			MaxRequestBodyBytes: l.envInt64("MAX_REQUEST_BODY_BYTES", 1<<20), // 1 MiB
			MaxPasswordLength:   l.envInt("MAX_PASSWORD_LENGTH", 72),
			RateLimiterEntryTTL: l.envDuration("RATE_LIMITER_ENTRY_TTL", 5*time.Minute),
			TOTPMaxConcurrent:   l.envInt("TOTP_MAX_CONCURRENT", 64),
		},
		Captcha: CaptchaConfig{
			Provider: l.env("CAPTCHA_PROVIDER", ""),
			Secret:   l.env("CAPTCHA_SECRET", ""),
			SiteKey:  l.env("CAPTCHA_SITE_KEY", ""),
		},
		GoogleOAuth: GoogleOAuthConfig{
			ClientID:     l.env("GOOGLE_CLIENT_ID", ""),
			ClientSecret: l.env("GOOGLE_CLIENT_SECRET", ""),
			RedirectURL:  l.env("GOOGLE_REDIRECT_URL", ""),
		},
		Audit: AuditConfig{
			BufferSize:    l.envInt("AUDIT_BUFFER_SIZE", 1024),
			FlushBatch:    l.envInt("AUDIT_FLUSH_BATCH", 64),
			RetentionDays: l.envInt("AUDIT_RETENTION_DAYS", 0),
		},
	}

	if cfg.JWT.Secret == "" {
		return nil, errJWTSecretMissing
	}
	// R2 — DB_TLS accepts exactly the go-sql-driver tls parameter values;
	// anything else would be appended to the DSN verbatim and fail (or worse,
	// misconfigure TLS) at connection time.
	switch cfg.DB.TLS {
	case "", "true", "skip-verify", "preferred":
	default:
		return nil, fmt.Errorf("config: DB_TLS=%q is invalid (want \"\", true, skip-verify, or preferred)", cfg.DB.TLS)
	}
	if err := errors.Join(l.errs...); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ----- helpers -----
//
// loader wraps the env readers with fail-fast semantics (R2): an explicitly
// set but unparseable value is a CONFIGURATION ERROR, not something to paper
// over with the default — a typo'd RATE_LIMIT_RPS=abc silently disabling a
// limiter is worse than a refused boot.

type loader struct{ errs []error }

func (l *loader) fail(key, value string, want string) {
	l.errs = append(l.errs, fmt.Errorf("config: %s=%q is not a valid %s", key, value, want))
}

func (l *loader) env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func (l *loader) envInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		l.fail(key, v, "integer")
	}
	return fallback
}

func (l *loader) envInt64(key string, fallback int64) int64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
		l.fail(key, v, "integer")
	}
	return fallback
}

func (l *loader) envBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
		l.fail(key, v, "boolean")
	}
	return fallback
}

func (l *loader) envFloat(key string, fallback float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		l.fail(key, v, "number")
	}
	return fallback
}

func (l *loader) envDuration(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		l.fail(key, v, "duration (e.g. 15m)")
	}
	return fallback
}

// envOptionalBool reads a boolean flag that distinguishes UNSET (nil) from
// an explicit false — RUN_JOBS semantics depend on the tri-state (S2). An
// explicitly set but unparseable value fails the boot (R2 semantics).
func (l *loader) envOptionalBool(key string) *bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.fail(key, v, "boolean")
		return nil
	}
	return &b
}

// TrimSpace centralises whitespace cleanup for request fields.
func TrimSpace(s string) string { return strings.TrimSpace(s) }

// envCSV reads a comma-separated env var into a trimmed slice. Returns nil
// (len 0) when unset/empty — which callers treat as "trust nothing".
func (l *loader) envCSV(key string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
