package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/jwt"
)

// AuditKeys is called before opening production stores or serving requests.
// Development may use ephemeral keys; production key history is operator held.
func (c *Config) AuditKeys() (*audit.Keys, error) {
	if c.Audit.SigningKeys == "" && c.Audit.CheckpointKey == "" && c.Audit.CheckpointKeys == "" && c.Server.GinMode != "release" {
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
	k, err := audit.NewKeyRing(c.Audit.KeyID, encoded, cpID, checkpoints)
	if err != nil {
		return nil, err
	}
	var materials [][]byte
	for _, value := range []string{c.JWT.Secret, c.JWT.PreviousSecret, c.JWT.StateSecret, c.JWT.StatePreviousSecret} {
		if value == "" {
			continue
		}
		b, err := jwt.DecodeStrongKey(value)
		if err != nil {
			return nil, errors.New("invalid authentication key encoding")
		}
		materials = append(materials, b)
	}
	// File providers override the environment value; main checks the resolved
	// recovery bytes as well, before opening a public listener.
	if c.Security.KeyProvider != "file" && c.Auth.RecoveryCodeKey != "" {
		b, err := hex.DecodeString(c.Auth.RecoveryCodeKey)
		if err != nil || len(b) != 32 {
			return nil, errors.New("invalid recovery key encoding")
		}
		materials = append(materials, b)
	}
	if err := k.RejectSharedMaterial(materials...); err != nil {
		return nil, err
	}
	return k, nil
}
