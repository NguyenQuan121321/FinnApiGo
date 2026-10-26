package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/finnapigo/finnapigo/internal/audit"
)

// AuditKeys is called before opening production stores or serving requests.
// Development may use ephemeral keys; production key history is operator held.
func (c *Config) AuditKeys() (*audit.Keys, error) {
	if c.Audit.SigningKeys == "" && c.Audit.CheckpointKey == "" && c.Server.GinMode != "release" {
		return audit.EphemeralKeys(), nil
	}
	var encoded map[string]string
	if json.Unmarshal([]byte(c.Audit.SigningKeys), &encoded) != nil {
		return nil, errors.New("AUDIT_SIGNING_KEYS must contain a versioned key map")
	}
	checkpoints := map[string]string{}
	cpID := c.Audit.CheckpointKeyID
	if cpID == "" {
		cpID = "checkpoint-v1"
	}
	if c.Audit.CheckpointKeys != "" {
		if json.Unmarshal([]byte(c.Audit.CheckpointKeys), &checkpoints) != nil {
			return nil, errors.New("invalid AUDIT_CHECKPOINT_KEYS")
		}
	} else {
		checkpoints[cpID] = c.Audit.CheckpointKey
	}
	all := make([]string, 0, len(encoded)+len(checkpoints))
	for _, v := range encoded {
		all = append(all, v)
	}
	for _, v := range checkpoints {
		all = append(all, v)
	}
	for _, value := range all {
		b, _ := base64.StdEncoding.DecodeString(value)
		for _, other := range []string{c.JWT.Secret, c.JWT.PreviousSecret, c.JWT.StateSecret, c.JWT.StatePreviousSecret, c.Auth.RecoveryCodeKey} {
			decodedHex, _ := hex.DecodeString(other)
			if other != "" && (string(b) == other || value == other || (len(decodedHex) > 0 && bytes.Equal(b, decodedHex))) {
				return nil, errors.New("audit keys must be separate from authentication/encryption keys")
			}
		}
	}
	return audit.NewKeyRing(c.Audit.KeyID, encoded, cpID, checkpoints)
}
