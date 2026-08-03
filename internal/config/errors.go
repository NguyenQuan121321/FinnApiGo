package config

import "errors"

// Sentinel errors for the config package.
var (
	errJWTSecretMissing = errors.New("config: JWT_SECRET must be set (see .env.example)")
)
