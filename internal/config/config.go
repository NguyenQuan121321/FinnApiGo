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
	Server   ServerConfig
	DB       DBConfig
	JWT      JWTConfig
	Auth     AuthConfig
	RateLimit RateLimitConfig
	SMTP     SMTPConfig
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
	OTPTTL               time.Duration
	OTPLength            int
	OTPMaxAttempts       int
}

type RateLimitConfig struct {
	RPS   float64
	Burst int
}

type SMTPConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
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
			MaxLoginAttempts:     envInt("MAX_LOGIN_ATTEMPTS", 5),
			LoginLockoutDuration: envDuration("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
			OTPTTL:               envDuration("OTP_TTL", 5*time.Minute),
			OTPLength:            envInt("OTP_LENGTH", 6),
			OTPMaxAttempts:       envInt("OTP_MAX_ATTEMPTS", 5),
		},
		RateLimit: RateLimitConfig{
			RPS:   envFloat("RATE_LIMIT_RPS", 5),
			Burst: envInt("RATE_LIMIT_BURST", 10),
		},
		SMTP: SMTPConfig{
			Host:     env("SMTP_HOST", ""),
			Port:     env("SMTP_PORT", "587"),
			User:     env("SMTP_USER", ""),
			Password: env("SMTP_PASSWORD", ""),
			From:     env("SMTP_FROM", "no-reply@finnapigo.local"),
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
