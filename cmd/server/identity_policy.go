package main

import (
	"fmt"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/identity"
	"github.com/finnapigo/finnapigo/internal/jwt"
)

// Validate before network/database setup; every deployment uses strict policy.
func identityPolicy(c *config.Config) (*jwt.JWTManager, identity.ServiceKeys, error) {
	if (c.Server.TLSCertFile == "") != (c.Server.TLSKeyFile == "") {
		return nil, identity.ServiceKeys{}, fmt.Errorf("both server TLS cert and key required")
	}
	k := identity.ServiceKeys{CurrentID: c.JWT.StateKeyID, CurrentSecret: c.JWT.StateSecret, PreviousID: c.JWT.StatePreviousKeyID, PreviousSecret: c.JWT.StatePreviousSecret}
	if c.JWT.Issuer != jwt.Issuer || c.JWT.AccessTTL <= 0 || c.JWT.AccessTTL > jwt.MaxAccessTTL {
		return nil, k, fmt.Errorf("identity issuer or access lifetime invalid")
	}
	if c.Server.GinMode == "release" && c.Redis.URL == "" {
		return nil, k, fmt.Errorf("shared Redis identity state required in release mode")
	}
	last, err := optionalUTC(c.JWT.PreviousLastIssued)
	if err != nil {
		return nil, k, err
	}
	k.PreviousUntil, err = optionalUTC(c.JWT.StatePreviousUntil)
	if err != nil {
		return nil, k, err
	}
	m, err := jwt.NewConfiguredJWTManager(jwt.KeyConfig{Algorithm: c.JWT.Algorithm, CurrentID: c.JWT.KeyID, CurrentSecret: c.JWT.Secret, PreviousID: c.JWT.PreviousKeyID, PreviousSecret: c.JWT.PreviousSecret, PreviousLastIssued: last})
	if err != nil {
		return nil, k, err
	}
	if err := identity.ValidateServiceKeys(k, c.JWT.Secret, c.JWT.PreviousSecret, c.Auth.RecoveryCodeKey, c.Server.MetricsToken, c.DB.Password, c.SMTP.Password, c.Captcha.Secret, c.GoogleOAuth.ClientSecret); err != nil {
		return nil, k, err
	}
	return m, k, nil
}

func optionalUTC(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("rotation timestamps require RFC3339 UTC Z")
	}
	return t, nil
}
