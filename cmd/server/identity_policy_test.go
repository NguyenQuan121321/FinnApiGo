package main

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
)

func syntheticPolicyKey(s string) string {
	b := sha256.Sum256([]byte("public F02 startup fixture " + s))
	return base64.StdEncoding.EncodeToString(b[:])
}
func TestIdentityStartupPolicy(t *testing.T) {
	base := config.Config{Server: config.ServerConfig{GinMode: "release"}, Redis: config.RedisConfig{URL: "redis://127.0.0.1:6379"}, JWT: config.JWTConfig{Algorithm: "HS256", Issuer: "finnapigo", Secret: syntheticPolicyKey("sign"), KeyID: "current", AccessTTL: 15 * time.Minute, StateSecret: syntheticPolicyKey("state"), StateKeyID: "service"}}
	m, k, err := identityPolicy(&base)
	if err != nil || !m.Strict() || k.CurrentID != "service" {
		t.Fatalf("policy %v", err)
	}
	for name, mutate := range map[string]func(*config.Config){"issuer": func(c *config.Config) { c.JWT.Issuer = "other" }, "ttl": func(c *config.Config) { c.JWT.AccessTTL = time.Hour }, "zero ttl": func(c *config.Config) { c.JWT.AccessTTL = 0 }, "Redis": func(c *config.Config) { c.Redis.URL = "" }, "partial TLS": func(c *config.Config) { c.Server.TLSCertFile = "cert" }, "algorithm": func(c *config.Config) { c.JWT.Algorithm = "RS256" }, "service reused": func(c *config.Config) { c.JWT.StateSecret = c.JWT.Secret }, "past timestamp parse": func(c *config.Config) { c.JWT.PreviousLastIssued = "invalid" }, "state timestamp parse": func(c *config.Config) { c.JWT.StatePreviousUntil = "invalid" }, "service absent": func(c *config.Config) { c.JWT.StateSecret = "" }} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if _, _, err := identityPolicy(&c); err == nil {
				t.Fatal("invalid startup accepted")
			}
		})
	}
	if _, err := optionalUTC("2026-01-01T00:00:00+07:00"); err == nil {
		t.Fatal("non UTC accepted")
	}
	if _, err := optionalUTC("2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}
