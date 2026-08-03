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
	Server    ServerConfig
	DB        DBConfig
	JWT       JWTConfig
	Auth      AuthConfig
	RateLimit RateLimitConfig
	SMTP      SMTPConfig
	Redis     RedisConfig
	Security  SecurityConfig
	Captcha   CaptchaConfig
	Audit     AuditConfig
}

type ServerConfig struct {
	Port   string
	GinMode string
}

type DBConfig struct {
	Host         string
	Port         string
	User         string
	Password     string
	Name         string
	MaxIdleConns int
	MaxOpenConns int
}

// DSN builds a MySQL DSN string for GORM.
func (d DBConfig) DSN() string {
	// charset=utf8mb4 to fully support emoji / 4-byte UTF-8.
	return d.User + ":" + d.Password + "@tcp(" + d.Host + ":" + d.Port + ")/" +
		d.Name + "?charset=utf8mb4&parseTime=True&loc=Local"
}

type JWTConfig struct {
	Secret  string
	Issuer  string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	ResetTTL   time.Duration
	VerifyTTL  time.Duration
}

type AuthConfig struct {
	MaxLoginAttempts     int
	LoginLockoutDuration time.Duration
	// MaxLockoutMultiplier caps the exponential backoff applied to repeat
	// offenders (§3). E.g. base 15m * min(lockoutCount, MaxLockoutMultiplier).
	MaxLockoutMultiplier int
	OTPTTL               time.Duration
	OTPLength            int
	OTPMaxAttempts       int
	// RequireEmailVerified gates sensitive actions behind is_email_verified
	// (§2). When true, login is still allowed (UX) but document it as a policy.
	RequireEmailVerified bool
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
	// OTP send limiter per user (§5).
	OTPSendPerUserMax int
	OTPSendWindow     time.Duration
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
	// MaxPasswordLength caps password length before bcrypt (§5).
	MaxPasswordLength int
	// RateLimiterEntryTTL bounds the per-IP rate-limiter map (§1.3).
	RateLimiterEntryTTL time.Duration
}

// CaptchaConfig drives the optional CAPTCHA on /register and post-fail /login.
// Secret empty => CAPTCHA disabled (NoOpVerifier). Provider selects the vendor.
type CaptchaConfig struct {
	Provider string // "turnstile" | "hcaptcha" | "" (= off)
	Secret   string
	SiteKey  string
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
			Port:    env("SERVER_PORT", "8080"),
			GinMode: env("GIN_MODE", "debug"),
		},
		DB: DBConfig{
			Host:         env("DB_HOST", "127.0.0.1"),
			Port:         env("DB_PORT", "3306"),
			User:         env("DB_USER", "finnapigo"),
			Password:     env("DB_PASSWORD", ""),
			Name:         env("DB_NAME", "finnapigo"),
			MaxIdleConns: envInt("DB_MAX_IDLE_CONNS", 10),
			MaxOpenConns: envInt("DB_MAX_OPEN_CONNS", 100),
		},
		JWT: JWTConfig{
			Secret:     env("JWT_SECRET", ""),
			Issuer:     env("JWT_ISSUER", "finnapigo"),
			AccessTTL:  envDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTTL: envDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
			ResetTTL:   envDuration("RESET_TOKEN_TTL", 15*time.Minute),
			VerifyTTL:  envDuration("EMAIL_VERIFY_TOKEN_TTL", 24*time.Hour),
		},
		Auth: AuthConfig{
			MaxLoginAttempts:      envInt("MAX_LOGIN_ATTEMPTS", 5),
			LoginLockoutDuration:  envDuration("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
			MaxLockoutMultiplier:  envInt("MAX_LOCKOUT_MULTIPLIER", 4),
			OTPTTL:                envDuration("OTP_TTL", 5*time.Minute),
			OTPLength:             envInt("OTP_LENGTH", 6),
			OTPMaxAttempts:        envInt("OTP_MAX_ATTEMPTS", 5),
			RequireEmailVerified:  envBool("REQUIRE_EMAIL_VERIFIED", false),
		},
		RateLimit: RateLimitConfig{
			RPS:                   envFloat("RATE_LIMIT_RPS", 5),
			Burst:                 envInt("RATE_LIMIT_BURST", 10),
			LoginPerAccountMax:    envInt("LOGIN_PER_ACCOUNT_MAX", 10),
			LoginWindow:           envDuration("LOGIN_WINDOW", 1*time.Minute),
			RegisterPerIPMax:      envInt("REGISTER_PER_IP_MAX", 5),
			RegisterWindow:        envDuration("REGISTER_WINDOW", 1*time.Hour),
			OTPSendPerUserMax:     envInt("OTP_SEND_PER_USER_MAX", 5),
			OTPSendWindow:         envDuration("OTP_SEND_WINDOW", 1*time.Hour),
			LoginCaptchaAfterFails: envInt("LOGIN_CAPTCHA_AFTER_FAILS", 5),
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
			MaxRequestBodyBytes:  envInt64("MAX_REQUEST_BODY_BYTES", 1<<20), // 1 MiB
			MaxPasswordLength:    envInt("MAX_PASSWORD_LENGTH", 128),
			RateLimiterEntryTTL:  envDuration("RATE_LIMITER_ENTRY_TTL", 5*time.Minute),
		},
		Captcha: CaptchaConfig{
			Provider: env("CAPTCHA_PROVIDER", ""),
			Secret:   env("CAPTCHA_SECRET", ""),
			SiteKey:  env("CAPTCHA_SITE_KEY", ""),
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
