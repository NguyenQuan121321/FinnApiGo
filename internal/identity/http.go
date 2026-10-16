package identity

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/gin-gonic/gin"
)

type ServiceKeys struct {
	CurrentID, CurrentSecret, PreviousID, PreviousSecret string
	PreviousUntil                                        time.Time
}

// ValidateServiceKeys prevents reuse of any configured application/signing key.
func ValidateServiceKeys(k ServiceKeys, applicationKeys ...string) error {
	if strings.TrimSpace(k.CurrentID) == "" {
		return fmt.Errorf("dedicated state key ID required")
	}
	if _, err := jwt.DecodeStrongKey(k.CurrentSecret); err != nil {
		return err
	}
	all := []string{k.CurrentSecret}
	if k.PreviousSecret != "" {
		if _, err := jwt.DecodeStrongKey(k.PreviousSecret); err != nil {
			return err
		}
		if k.PreviousID == "" || k.PreviousID == k.CurrentID || k.PreviousSecret == k.CurrentSecret || k.PreviousUntil.IsZero() || k.PreviousUntil.After(time.Now().Add(jwt.KeyDrain)) {
			return fmt.Errorf("bounded distinct previous state credential required")
		}
		all = append(all, k.PreviousSecret)
	} else if k.PreviousID != "" || !k.PreviousUntil.IsZero() {
		return fmt.Errorf("incomplete state credential rotation")
	}
	for _, s := range all {
		for _, other := range applicationKeys {
			same := s == other
			decoded, _ := base64.StdEncoding.DecodeString(s)
			if b, err := base64.StdEncoding.DecodeString(other); err == nil && len(b) > 0 {
				same = same || bytes.Equal(decoded, b)
			}
			if b, err := hex.DecodeString(other); err == nil && len(b) > 0 {
				same = same || bytes.Equal(decoded, b)
			}
			if other != "" && same {
				return fmt.Errorf("state credential must be distinct from application keys")
			}
		}
	}
	return nil
}

type Handler struct {
	JWT       *jwt.JWTManager
	Authority *Authority
	Keys      ServiceKeys
}

// POST accepts only a JWT and expected tenant; service identity is fixed to
// jakeai-service and can introspect only a user JWT granting its own audience.
// X-Forwarded-Proto is never a TLS authority here. Use actual TLS termination
// on the private route or a trusted ingress that preserves authenticated TLS.
func (h *Handler) Handle(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if c.Request.TLS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tls_required"})
		return
	}
	kid := c.GetHeader("X-Service-Key-ID")
	secret := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	valid := kid == h.Keys.CurrentID && subtle.ConstantTimeCompare([]byte(secret), []byte(h.Keys.CurrentSecret)) == 1
	if !valid && kid == h.Keys.PreviousID && time.Now().Before(h.Keys.PreviousUntil) {
		valid = subtle.ConstantTimeCompare([]byte(secret), []byte(h.Keys.PreviousSecret)) == 1
	}
	if !valid || !strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_service_credential"})
		return
	}
	if h.Authority == nil || h.Authority.Store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "state_unavailable"})
		return
	}
	allowed, err := h.Authority.Store.Admit(c.Request.Context(), "identity:service:jakeai-service", 120, time.Second)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "state_unavailable"})
		return
	}
	if !allowed {
		c.Header("Retry-After", "1")
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16384)
	var in struct {
		Token    string `json:"token"`
		TenantID string `json:"tenant_id"`
	}
	if err := c.ShouldBindJSON(&in); err != nil || in.TenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	claims, err := h.JWT.VerifyAccessV1(in.Token, jwt.JakeAudience)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"active": false})
		return
	}
	if claims.TenantID != in.TenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant_denied"})
		return
	}
	if err := h.Authority.Check(c.Request.Context(), claims); err != nil {
		if errors.Is(err, ErrInactive) {
			c.JSON(http.StatusUnauthorized, gin.H{"active": false})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "state_unavailable"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"contract_ver": 1, "active": true, "tid": claims.TenantID, "sub": claims.Subject, "sid": claims.SID, "jti": claims.ID, "pwdver": claims.PwdVer, "auth_epoch": claims.AuthEpoch, "checked_at": time.Now().UTC().Unix(), "max_cache_seconds": 15})
}
