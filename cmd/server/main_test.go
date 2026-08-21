package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/config"
)

func TestRecoveryEncryptionKey_ReleaseModeRequiresExplicitKey_K1(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{GinMode: gin.ReleaseMode},
		JWT:    config.JWTConfig{Secret: "unit-test-jwt-secret"},
		Auth:   config.AuthConfig{RecoveryCodeKey: ""},
	}
	_, err := recoveryEncryptionKey(cfg)
	if err == nil {
		t.Fatal("K1: release mode must refuse to boot without RECOVERY_CODE_KEY, got nil error")
	}
	if !strings.Contains(err.Error(), "RECOVERY_CODE_KEY") {
		t.Fatalf("K1: error must name RECOVERY_CODE_KEY, got: %v", err)
	}
}

func TestRecoveryEncryptionKey_DevModeDerivesWithWarning_K1(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{GinMode: gin.DebugMode},
		JWT:    config.JWTConfig{Secret: "unit-test-jwt-secret"},
		Auth:   config.AuthConfig{RecoveryCodeKey: ""},
	}
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
	cfg := &config.Config{
		Server: config.ServerConfig{GinMode: gin.ReleaseMode},
		JWT:    config.JWTConfig{Secret: "unit-test-jwt-secret"},
		Auth:   config.AuthConfig{RecoveryCodeKey: raw},
	}
	key, err := recoveryEncryptionKey(cfg)
	if err != nil {
		t.Fatalf("explicit valid key must be accepted in release mode: %v", err)
	}
	if want, _ := hex.DecodeString(raw); hex.EncodeToString(key) != hex.EncodeToString(want) {
		t.Fatal("explicit key must be used verbatim")
	}
}

func TestRecoveryEncryptionKey_ExplicitInvalidKeyRejected_K1(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{GinMode: gin.DebugMode},
		JWT:    config.JWTConfig{Secret: "unit-test-jwt-secret"},
		Auth:   config.AuthConfig{RecoveryCodeKey: "not-hex"},
	}
	if _, err := recoveryEncryptionKey(cfg); err == nil {
		t.Fatal("invalid RECOVERY_CODE_KEY must be rejected in every mode")
	}
}
