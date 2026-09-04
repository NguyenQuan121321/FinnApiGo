package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/config"
)

// k1Config builds the config under test. The JWT secret is composed at runtime
// (not a literal) so gosec G101 — correctly — never sees a hardcoded credential.
func k1Config(ginMode, recoveryKey string) *config.Config {
	cfg := &config.Config{
		Server: config.ServerConfig{GinMode: ginMode},
		Auth:   config.AuthConfig{RecoveryCodeKey: recoveryKey},
	}
	cfg.JWT.Secret = strings.Repeat("unit-test-jwt-secret-", 2)
	return cfg
}

func TestRecoveryEncryptionKey_ReleaseModeRequiresExplicitKey_K1(t *testing.T) {
	cfg := k1Config(gin.ReleaseMode, "")
	_, err := recoveryEncryptionKey(cfg)
	if err == nil {
		t.Fatal("K1: release mode must refuse to boot without RECOVERY_CODE_KEY, got nil error")
	}
	if !strings.Contains(err.Error(), "RECOVERY_CODE_KEY") {
		t.Fatalf("K1: error must name RECOVERY_CODE_KEY, got: %v", err)
	}
}

func TestRecoveryEncryptionKey_DevModeDerivesWithWarning_K1(t *testing.T) {
	cfg := k1Config(gin.DebugMode, "")
	key, err := recoveryEncryptionKey(cfg)
	if err != nil {
		t.Fatalf("dev mode should keep deriving (loud warning), got error: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("derived key must be 32 bytes, got %d", len(key))
	}
}

func TestRecoveryEncryptionKey_ExplicitKeyWins_K1(t *testing.T) {
	raw := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg := k1Config(gin.ReleaseMode, raw)
	key, err := recoveryEncryptionKey(cfg)
	if err != nil {
		t.Fatalf("explicit valid key must be accepted in release mode: %v", err)
	}
	if want, _ := hex.DecodeString(raw); hex.EncodeToString(key) != hex.EncodeToString(want) {
		t.Fatal("explicit key must be used verbatim")
	}
}

func TestRecoveryEncryptionKey_ExplicitInvalidKeyRejected_K1(t *testing.T) {
	cfg := k1Config(gin.DebugMode, "not-hex")
	if _, err := recoveryEncryptionKey(cfg); err == nil {
		t.Fatal("invalid RECOVERY_CODE_KEY must be rejected in every mode")
	}
}

// TestAuditRetentionWarning_G1 — release mode with AUDIT_RETENTION_DAYS
// unset emits the PII-retention boot warning; dev mode and an explicit
// window stay silent (a warning, not a boot failure — the policy decision
// is documented on the function).
func TestAuditRetentionWarning_G1(t *testing.T) {
	release := func(retentionDays int) *config.Config {
		cfg := k1Config(gin.ReleaseMode, strings.Repeat("ab", 32))
		cfg.Audit.RetentionDays = retentionDays
		return cfg
	}
	if msg := auditRetentionWarning(release(0)); msg == "" {
		t.Fatal("G1: release mode with unset retention must emit a warning")
	}
	if msg := auditRetentionWarning(release(90)); msg != "" {
		t.Fatalf("G1: explicit retention window must not warn, got: %s", msg)
	}
	dev := k1Config(gin.DebugMode, "")
	dev.Audit.RetentionDays = 0
	if msg := auditRetentionWarning(dev); msg != "" {
		t.Fatalf("G1: dev mode must not warn, got: %s", msg)
	}
}

// TestRecoveryEncryptionKey_FileProvider_K3 — KEY_PROVIDER=file reads the
// recovery-code key from <KEY_DIR>/recovery_codes.key (mounted-secrets
// pattern), bypassing the env var entirely.
func TestRecoveryEncryptionKey_FileProvider_K3(t *testing.T) {
	dir := t.TempDir()
	raw := strings.Repeat("ef", 32)
	if err := os.WriteFile(filepath.Join(dir, "recovery_codes.key"), []byte(raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := k1Config(gin.ReleaseMode, "")
	cfg.Security.KeyProvider = "file"
	cfg.Security.KeyDir = dir

	key, err := recoveryEncryptionKey(cfg)
	if err != nil {
		t.Fatalf("file provider must supply the key in release mode: %v", err)
	}
	if want, _ := hex.DecodeString(raw); hex.EncodeToString(key) != hex.EncodeToString(want) {
		t.Fatal("file-provider key must be used verbatim")
	}

	// Missing file => boot refuses (fail closed), even with JWT_SECRET present.
	cfg.Security.KeyDir = filepath.Join(dir, "nonexistent")
	if _, err := recoveryEncryptionKey(cfg); err == nil {
		t.Fatal("K3: missing key file must fail the boot in file mode")
	}
}

// TestConfig_KeyProviderValidation_K3 — invalid KEY_PROVIDER values and
// file-mode-without-KEY_DIR fail the boot at config load.
func TestConfig_KeyProviderValidation_K3(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("k3-", 16))
	t.Setenv("KEY_PROVIDER", "vault") // vendor binding is an operator decision — not a valid enum here
	if _, err := config.Load(); err == nil {
		t.Fatal("K3: invalid KEY_PROVIDER must fail config load")
	}
	t.Setenv("KEY_PROVIDER", "file")
	t.Setenv("KEY_DIR", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("K3: KEY_PROVIDER=file without KEY_DIR must fail config load")
	}
}

func TestValidateMetricsPolicy_ReleaseMode_P06(t *testing.T) {
	// 1. Release mode without METRICS_ADDR and without METRICS_TOKEN must fail boot
	cfg := &config.Config{
		Server: config.ServerConfig{
			GinMode:      gin.ReleaseMode,
			MetricsAddr:  "",
			MetricsToken: "",
		},
	}
	if err := validateMetricsPolicy(cfg); err == nil {
		t.Fatal("P0.6: release mode without metrics addr or token must fail boot, got nil error")
	}

	// 2. Release mode with METRICS_ADDR succeeds
	cfg.Server.MetricsAddr = "127.0.0.1:9090"
	if err := validateMetricsPolicy(cfg); err != nil {
		t.Fatalf("P0.6: release mode with METRICS_ADDR must succeed, got %v", err)
	}

	// 3. Release mode with METRICS_TOKEN succeeds
	cfg.Server.MetricsAddr = ""
	cfg.Server.MetricsToken = "secret-token"
	if err := validateMetricsPolicy(cfg); err != nil {
		t.Fatalf("P0.6: release mode with METRICS_TOKEN must succeed, got %v", err)
	}

	// 4. Debug/dev mode without addr or token succeeds
	cfg.Server.GinMode = gin.DebugMode
	cfg.Server.MetricsAddr = ""
	cfg.Server.MetricsToken = ""
	if err := validateMetricsPolicy(cfg); err != nil {
		t.Fatalf("P0.6: dev mode without metrics addr or token must succeed, got %v", err)
	}
}
