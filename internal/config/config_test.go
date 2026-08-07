package config

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		assert  func(*testing.T, *Config)
	}{
		{name: "missing secret", env: map[string]string{"JWT_SECRET": ""}, wantErr: true},
		{name: "configured", env: map[string]string{"JWT_SECRET": "test-secret", "SERVER_PORT": "9443", "ACCESS_TOKEN_TTL": "20m", "RATE_LIMIT_RPS": "9.5"}, assert: func(t *testing.T, c *Config) {
			if c.Server.Port != "9443" || c.JWT.AccessTTL != 20*time.Minute || c.RateLimit.RPS != 9.5 {
				t.Fatalf("unexpected config: %+v", c)
			}
		}},
		{name: "malformed duration falls back", env: map[string]string{"JWT_SECRET": "test-secret", "ACCESS_TOKEN_TTL": "notaduration"}, assert: func(t *testing.T, c *Config) {
			if c.JWT.AccessTTL != 15*time.Minute {
				t.Fatalf("AccessTTL=%v", c.JWT.AccessTTL)
			}
		}},
		{name: "optional defaults", env: map[string]string{"JWT_SECRET": "test-secret"}, assert: func(t *testing.T, c *Config) {
			if c.RateLimit.RPS != 5 || c.Server.Port != "8080" {
				t.Fatalf("unexpected defaults: %+v", c)
			}
		}},
	}
	keys := []string{"JWT_SECRET", "SERVER_PORT", "ACCESS_TOKEN_TTL", "RATE_LIMIT_RPS"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range keys {
				t.Setenv(key, "")
			}
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			got, err := Load()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load error=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil {
				tc.assert(t, got)
			}
		})
	}
}

func TestDBConfigDSN(t *testing.T) {
	dsn := (DBConfig{Host: "db", Port: "3307", User: "app", Password: "secret", Name: "finn"}).DSN()
	if dsn != "app:secret@tcp(db:3307)/finn?charset=utf8mb4&parseTime=True&loc=Local" {
		t.Fatalf("DSN=%q", dsn)
	}
}
