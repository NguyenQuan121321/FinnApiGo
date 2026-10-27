package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"strings"
	"testing"
)

func TestReviewF03RejectDecodedAuthenticationKeyReuse(t *testing.T) {
	key := func(label string) string {
		b := sha256.Sum256([]byte("PUBLIC SYNTHETIC REVIEW " + label))
		return base64.StdEncoding.EncodeToString(b[:])
	}
	auth := key("auth")
	c := &Config{Server: ServerConfig{GinMode: "release"}}
	c.JWT.Secret = auth
	c.Audit.KeyID = "audit"
	c.Audit.CheckpointKey = key("checkpoint")
	if _, err := jwt.NewConfiguredJWTManager(jwt.KeyConfig{Algorithm: "HS256", CurrentID: "auth", CurrentSecret: auth}); err != nil {
		t.Fatal("synthetic JWT fixture invalid")
	}
	for _, alter := range []bool{false, true} {
		name := "canonical_control"
		value := auth
		if alter {
			name = "line_wrapped_same_bytes"
			value = auth[:16] + "\n" + auth[16:]
		}
		t.Run(name, func(t *testing.T) {
			b, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				t.Fatal("alternate encoding invalid")
			}
			original, _ := base64.StdEncoding.DecodeString(auth)
			if string(b) != string(original) {
				t.Fatal("fixture bytes differ")
			}
			raw, _ := json.Marshal(map[string]string{"audit": value})
			c.Audit.SigningKeys = string(raw)
			if _, err := c.AuditKeys(); err == nil {
				t.Fatal("release audit key validation accepted authentication signing bytes reused under alternate encoding")
			}
		})
	}
}

func TestF03KeyPurposeAndEncodingMatrix(t *testing.T) {
	key := func(label string) string {
		b := sha256.Sum256([]byte("F03 repair synthetic " + label))
		return base64.StdEncoding.EncodeToString(b[:])
	}
	shared := key("shared")
	raw, _ := base64.StdEncoding.DecodeString(shared)
	for _, domain := range []string{"jwt", "previous-jwt", "state", "previous-state", "recovery-lower", "recovery-upper"} {
		for _, slot := range []string{"active-signing", "retained-signing", "active-checkpoint", "retained-checkpoint", "single-checkpoint"} {
			t.Run(domain+"/"+slot, func(t *testing.T) {
				c := &Config{Server: ServerConfig{GinMode: "release"}}
				c.Audit.KeyID, c.Audit.CheckpointKeyID = "active", "active-cp"
				signing := map[string]string{"active": key("signing"), "retained": key("old-signing")}
				checkpoints := map[string]string{"active-cp": key("checkpoint"), "retained-cp": key("old-checkpoint")}
				switch domain {
				case "jwt":
					c.JWT.Secret = shared
				case "previous-jwt":
					c.JWT.PreviousSecret = shared
				case "state":
					c.JWT.StateSecret = shared
				case "previous-state":
					c.JWT.StatePreviousSecret = shared
				case "recovery-lower":
					c.Auth.RecoveryCodeKey = hex.EncodeToString(raw)
				case "recovery-upper":
					c.Auth.RecoveryCodeKey = strings.ToUpper(hex.EncodeToString(raw))
				}
				switch slot {
				case "active-signing":
					signing["active"] = shared
				case "retained-signing":
					signing["retained"] = shared
				case "active-checkpoint", "single-checkpoint":
					checkpoints["active-cp"] = shared
				case "retained-checkpoint":
					checkpoints["retained-cp"] = shared
				}
				b, _ := json.Marshal(signing)
				c.Audit.SigningKeys = string(b)
				b, _ = json.Marshal(checkpoints)
				c.Audit.CheckpointKeys = string(b)
				if slot == "single-checkpoint" {
					c.Audit.CheckpointKeys = ""
					c.Audit.CheckpointKey = shared
				}
				if _, err := c.AuditKeys(); err == nil {
					t.Fatal("decoded key reuse accepted")
				} else if strings.Contains(err.Error(), shared) || strings.Contains(err.Error(), hex.EncodeToString(raw)) {
					t.Fatal("error exposed material")
				}
			})
		}
	}
	// Alternate encodings that decode to identical bytes are unsupported in
	// every Base64 slot (including retained keys), even without key reuse.
	for _, alter := range []func(string) string{
		func(s string) string { return s[:16] + "\r\n" + s[16:] },
		func(s string) string { return strings.TrimRight(s, "=") },
		func(s string) string {
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			i := strings.IndexByte(alphabet, s[len(s)-2])
			return s[:len(s)-2] + string(alphabet[i+1]) + "="
		},
	} {
		for _, slot := range []string{"signing", "checkpoint", "jwt", "previous-jwt", "state", "previous-state"} {
			c := &Config{Server: ServerConfig{GinMode: "release"}}
			c.Audit.KeyID = "active"
			signing := map[string]string{"active": key("signing")}
			c.Audit.CheckpointKey = key("checkpoint")
			value := alter(shared)
			switch slot {
			case "signing":
				signing["old"] = value
			case "checkpoint":
				b, _ := json.Marshal(map[string]string{"checkpoint-v1": c.Audit.CheckpointKey, "old": value})
				c.Audit.CheckpointKeys = string(b)
			case "jwt":
				c.JWT.Secret = value
			case "previous-jwt":
				c.JWT.PreviousSecret = value
			case "state":
				c.JWT.StateSecret = value
			case "previous-state":
				c.JWT.StatePreviousSecret = value
			}
			b, _ := json.Marshal(signing)
			c.Audit.SigningKeys = string(b)
			if _, err := c.AuditKeys(); err == nil {
				t.Fatalf("noncanonical %s accepted", slot)
			}
		}
	}
	c := &Config{}
	c.Audit.CheckpointKeys = "malformed"
	if _, err := c.AuditKeys(); err == nil {
		t.Fatal("configured checkpoint map bypassed through dev fallback")
	}
	c = &Config{Server: ServerConfig{GinMode: "release"}}
	c.Audit.KeyID = "active"
	b, _ := json.Marshal(map[string]string{"active": key("signing")})
	c.Audit.SigningKeys, c.Audit.CheckpointKey = string(b), key("checkpoint")
	c.JWT.Secret, c.JWT.PreviousSecret = key("jwt"), key("old-jwt")
	c.JWT.StateSecret, c.JWT.StatePreviousSecret = key("state"), key("old-state")
	c.Auth.RecoveryCodeKey = hex.EncodeToString(raw)
	if _, err := c.AuditKeys(); err != nil {
		t.Fatal("distinct supported encodings rejected", err)
	}
	for _, invalid := range []string{"invalid-hex", "00"} {
		c.Auth.RecoveryCodeKey = invalid
		if _, err := c.AuditKeys(); err == nil {
			t.Fatal("invalid recovery encoding accepted")
		}
	}
	c.Security.KeyProvider = "file"
	if _, err := c.AuditKeys(); err != nil {
		t.Fatal("inactive environment recovery value rejected", err)
	}
}
