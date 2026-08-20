package config

import (
	"strings"
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
		// R2 — an explicitly invalid value is a configuration error now;
		// this case pinned the old silent-fallback behavior the fix removes.
		{name: "malformed duration fails boot", env: map[string]string{"JWT_SECRET": "test-secret", "ACCESS_TOKEN_TTL": "notaduration"}, wantErr: true},
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
	if dsn != "app:secret@tcp(db:3307)/finn?charset=utf8mb4&parseTime=True&loc=UTC" {
		t.Fatalf("DSN=%q", dsn)
	}
}

func TestDBConfigDSNWithTLS(t *testing.T) {
	dsn := (DBConfig{Host: "db", Port: "3307", User: "app", Password: "secret", Name: "finn", TLS: "true"}).DSN()
	want := "app:secret@tcp(db:3307)/finn?charset=utf8mb4&parseTime=True&loc=UTC&tls=true"
	if dsn != want {
		t.Fatalf("DSN=%q want %q", dsn, want)
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
			got := (&loader{}).envCSV("TEST_CSV_PROXY")
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

// TestLoad_FailFastInvalidValues_R2 — R2 regression: explicitly set but
// unparseable numeric/duration/bool env values must fail the boot with an
// error naming the variable, never silently fall back to a default (which
// would e.g. disable a rate limiter on a typo).
func TestLoad_FailFastInvalidValues_R2(t *testing.T) {
	cases := []struct{ key, value string }{
		{"RATE_LIMIT_RPS", "abc"},           // float
		{"HSTS_SECONDS", "notanint"},        // int
		{"AUDIT_BUFFER_SIZE", "1.5"},        // int
		{"ACCESS_TOKEN_TTL", "nope"},        // duration
		{"LOGIN_WINDOW", "tomorrow"},        // duration
		{"REQUIRE_EMAIL_VERIFIED", "maybe"}, // bool
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			t.Setenv("JWT_SECRET", "test-secret")
			t.Setenv(tc.key, tc.value)
			cfg, err := Load()
			if err == nil {
				t.Fatalf("%s=%s must fail boot, got cfg %+v", tc.key, tc.value, cfg)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error must name the offending variable %s: %v", tc.key, err)
			}
		})
	}
}

// TestLoad_DBTLSValidation_R2 — R2: DB_TLS only accepts the go-sql-driver
// parameter values; anything else fails the boot instead of landing in the
// DSN verbatim.
func TestLoad_DBTLSValidation_R2(t *testing.T) {
	for _, valid := range []string{"", "true", "skip-verify", "preferred"} {
		t.Setenv("JWT_SECRET", "test-secret")
		t.Setenv("DB_TLS", valid)
		if _, err := Load(); err != nil {
			t.Fatalf("DB_TLS=%q must be accepted: %v", valid, err)
		}
	}
	t.Setenv("DB_TLS", "bogus")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DB_TLS") {
		t.Fatalf("DB_TLS=bogus must fail with a clear error, got %v", err)
	}
}

// TestDBConfigDSN_LocUTC_R3 — R3: the DSN must pin loc=UTC so every parsed
// DATETIME is normalized to UTC regardless of the host's local timezone.
func TestDBConfigDSN_LocUTC_R3(t *testing.T) {
	dsn := (DBConfig{Host: "db", Port: "3306", User: "u", Password: "p", Name: "n"}).DSN()
	if !strings.Contains(dsn, "loc=UTC") {
		t.Fatalf("DSN must carry loc=UTC: %q", dsn)
	}
	if strings.Contains(dsn, "loc=Local") {
		t.Fatalf("DSN must not use loc=Local: %q", dsn)
	}
}

// TestLoad_MigrateAutoDefaultOff_R1 — R1: AutoMigrate at boot must be
// opt-in; the default (unset) posture is "schema comes from migrations".
func TestLoad_MigrateAutoDefaultOff_R1(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("MIGRATE_AUTO", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB.MigrateAuto {
		t.Fatal("MIGRATE_AUTO must default to false")
	}
	t.Setenv("MIGRATE_AUTO", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DB.MigrateAuto {
		t.Fatal("MIGRATE_AUTO=true must enable the dev escape hatch")
	}
}
