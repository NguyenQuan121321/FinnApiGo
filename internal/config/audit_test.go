package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestProductionAuditKeys(t *testing.T) {
	key := func(s string) string { v := sha256.Sum256([]byte(s)); return base64.StdEncoding.EncodeToString(v[:]) }
	c := &Config{Server: ServerConfig{GinMode: "release"}}
	if _, err := c.AuditKeys(); err == nil {
		t.Fatal("production boot accepted missing keys")
	}
	c.Audit.SigningKeys = `{"k":"YXVkaXQtaGFzaC1jaGFpbi1kZWZhdWx0LXNlY3JldC0zMmI="}`
	c.Audit.KeyID = "k"
	c.Audit.CheckpointKey = key("cp")
	if _, err := c.AuditKeys(); err == nil {
		t.Fatal("public default accepted")
	}
	b, _ := json.Marshal(map[string]string{"k": key("audit")})
	c.Audit.SigningKeys = string(b)
	if _, err := c.AuditKeys(); err != nil {
		t.Fatal(err)
	}
	c.JWT.Secret = key("audit")
	if _, err := c.AuditKeys(); err == nil {
		t.Fatal("auth key reuse accepted")
	}
	c = &Config{}
	if _, err := c.AuditKeys(); err != nil {
		t.Fatal("dev ephemeral", err)
	}
	c.Audit.SigningKeys = "bad"
	if _, err := c.AuditKeys(); err == nil {
		t.Fatal("malformed configured keys accepted")
	}
}
