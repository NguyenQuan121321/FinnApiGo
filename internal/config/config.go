// Package config loads configuration from environment variables (.env supported).
// No hardcoded secrets or lifetimes anywhere in the codebase — everything is read here.
package config

import (
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
}

// DSN builds a MySQL DSN string for GORM.
func (d DBConfig) DSN() string {
	// charset=utf8mb4 to fully support emoji / 4-byte UTF-8.
	dsn := d.User + ":" + d.Password + "@tcp(" + d.Host + ":" + d.Port + ")/" +
		d.Name + "?charset=utf8mb4&parseTime=True&loc=Local"
	if d.TLS != "" {
		dsn += "&tls=" + d.TLS
	}
	return dsn
}

type JWTConfig struct {
	Secret        string
	Issuer        string
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
}

// Load reads .env (if present) and environment variables, applying sane defaults
// only for non-secret values. JWT secret has NO default — it must be set.
func Load() (*Config, error) {
	// .env is optional in production (env may be injected directly).
	_ = godotenv.Load()

	cfg := &Config{
		Server: ServerConfig{
			Port:           env("SERVER_PORT", "8080"),
			GinMode:        env("GIN_MODE", "debug"),
			TrustedProxies: envCSV("TRUSTED_PROXIES"),
			PProfAddr:      env("PPROF_ADDR", ""),
			HSTSSeconds:    envInt("HSTS_SECONDS", 0),
		},
		DB: DBConfig{
			Host:         env("DB_HOST", "127.0.0.1"),
			Port:         env("DB_PORT", "3306"),
			User:         env("DB_USER", "finnapigo"),
			Password:     env("DB_PASSWORD", ""),
			Name:         env("DB_NAME", "finnapigo"),
			MaxIdleConns: envInt("DB_MAX_IDLE_CONNS", 10),
			MaxOpenConns: envInt("DB_MAX_OPEN_CONNS", 100),
			TLS:          env("DB_TLS", ""),
		},
		JWT: JWTConfig{
			Secret:        env("JWT_SECRET", ""),
			Issuer:        env("JWT_ISSUER", "finnapigo"),
			AccessTTL:     envDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTTL:    envDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
			ResetTTL:      envDuration("RESET_TOKEN_TTL", 15*time.Minute),
			VerifyTTL:     envDuration("EMAIL_VERIFY_TOKEN_TTL", 24*time.Hour),
			MFAPendingTTL: envDuration("MFA_PENDING_TOKEN_TTL", 5*time.Minute),
			SudoTTL:       envDuration("SUDO_TOKEN_TTL", 15*time.Minute),
		},
		Auth: AuthConfig{
			MaxLoginAttempts:     envInt("MAX_LOGIN_ATTEMPTS", 5),
			LoginLockoutDuration: envDuration("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
			MaxLockoutMultiplier: envInt("MAX_LOCKOUT_MULTIPLIER", 4),
			RequireEmailVerified: envBool("REQUIRE_EMAIL_VERIFIED", false),
			TOTPMaxAttempts:      envInt("TOTP_MAX_ATTEMPTS", 5),
			TOTPAttemptWindow:    envDuration("TOTP_ATTEMPT_WINDOW", 5*time.Minute),
			RecoveryCodeCount:    envInt("RECOVERY_CODE_COUNT", 10),
			RecoveryCodeBytes:    envInt("RECOVERY_CODE_BYTES", 16),
			RecoveryCodeKey:      env("RECOVERY_CODE_KEY", ""),
		},
		RateLimit: RateLimitConfig{
			RPS:                      envFloat("RATE_LIMIT_RPS", 5),
			Burst:                    envInt("RATE_LIMIT_BURST", 10),
			LoginPerAccountMax:       envInt("LOGIN_PER_ACCOUNT_MAX", 10),
			LoginWindow:              envDuration("LOGIN_WINDOW", 1*time.Minute),
			RegisterPerIPMax:         envInt("REGISTER_PER_IP_MAX", 5),
			RegisterWindow:           envDuration("REGISTER_WINDOW", 1*time.Hour),
			VerifyResendPerEmailMax:  envInt("VERIFY_RESEND_PER_EMAIL_MAX", 3),
			VerifyResendWindow:       envDuration("VERIFY_RESEND_WINDOW", 1*time.Hour),
			VerifyResendGlobalMax:    envInt("VERIFY_RESEND_GLOBAL_MAX", 100),
			VerifyResendGlobalWindow: envDuration("VERIFY_RESEND_GLOBAL_WINDOW", 1*time.Hour),
			VerifyResendPerIPMax:     envInt("VERIFY_RESEND_PER_IP_MAX", 5),
			VerifyResendPerIPWindow:  envDuration("VERIFY_RESEND_PER_IP_WINDOW", 1*time.Hour),
			LoginCaptchaAfterFails:   envInt("LOGIN_CAPTCHA_AFTER_FAILS", 5),
		},
		SMTP: SMTPConfig{
			Host:     env("SMTP_HOST", ""),
			Port:     env("SMTP_PORT", "587"),
			User:     env("SMTP_USER", ""),
			Password: env("SMTP_PASSWORD", ""),
			From:     env("SMTP_FROM", "no-reply@finnapigo.local"),
		},
		Redis: RedisConfig{
			URL: env("REDIS_URL", ""),
		},
		Security: SecurityConfig{
			MaxRequestBodyBytes: envInt64("MAX_REQUEST_BODY_BYTES", 1<<20), // 1 MiB
			MaxPasswordLength:   envInt("MAX_PASSWORD_LENGTH", 72),
			RateLimiterEntryTTL: envDuration("RATE_LIMITER_ENTRY_TTL", 5*time.Minute),
			TOTPMaxConcurrent:   envInt("TOTP_MAX_CONCURRENT", 64),
		},
		Captcha: CaptchaConfig{
			Provider: env("CAPTCHA_PROVIDER", ""),
			Secret:   env("CAPTCHA_SECRET", ""),
			SiteKey:  env("CAPTCHA_SITE_KEY", ""),
		},
		GoogleOAuth: GoogleOAuthConfig{
			ClientID:     env("GOOGLE_CLIENT_ID", ""),
			ClientSecret: env("GOOGLE_CLIENT_SECRET", ""),
			RedirectURL:  env("GOOGLE_REDIRECT_URL", ""),
		},
		Audit: AuditConfig{
			BufferSize: envInt("AUDIT_BUFFER_SIZE", 1024),
			FlushBatch: envInt("AUDIT_FLUSH_BATCH", 64),
		},
	}

	if cfg.JWT.Secret == "" {
		return nil, errJWTSecretMissing
	}
	return cfg, nil
}

// ----- helpers -----

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

// TrimSpace centralises whitespace cleanup for request fields.
func TrimSpace(s string) string { return strings.TrimSpace(s) }

// envCSV reads a comma-separated env var into a trimmed slice. Returns nil
// (len 0) when unset/empty — which callers treat as "trust nothing".
func envCSV(key string) []string {
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
