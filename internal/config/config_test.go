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

func TestEnvCSV(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []string
	}{
		{"unset", "", nil},
		{"whitespace only", "  ", nil},
		{"single", "10.0.0.1", []string{"10.0.0.1"}},
		{"multiple", "10.0.0.1, 172.16.0.0/12", []string{"10.0.0.1", "172.16.0.0/12"}},
		{"trims spaces", "  a , b , c  ", []string{"a", "b", "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_CSV_PROXY", tc.env)
			got := envCSV("TEST_CSV_PROXY")
			if len(got) != len(tc.want) {
				t.Fatalf("len=%d want=%d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestLoad_TrustedProxies(t *testing.T) {
	// Ensure TrustedProxies is nil (secure default) when unset.
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("TRUSTED_PROXIES", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.TrustedProxies != nil {
		t.Fatalf("expected nil TrustedProxies, got %v", cfg.Server.TrustedProxies)
	}
	// When set, should parse into a slice.
	t.Setenv("TRUSTED_PROXIES", "10.0.0.1, 172.16.0.0/12")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.TrustedProxies) != 2 || cfg.Server.TrustedProxies[0] != "10.0.0.1" {
		t.Fatalf("TrustedProxies=%v", cfg.Server.TrustedProxies)
	}
}
