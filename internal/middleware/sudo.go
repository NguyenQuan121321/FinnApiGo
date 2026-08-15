package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/response"
)

// SudoHeader is the header carrying the short-lived sudo token minted after a
// successful TOTP verification on the recovery-codes view endpoint.
const SudoHeader = "X-Sudo-Token"

// SudoMiddleware enforces GitHub-style "sudo mode" for sensitive endpoints
// (e.g. regenerating recovery codes). It must be chained AFTER AuthMiddleware:
// the caller is already authenticated, and this middleware additionally
// requires an X-Sudo-Token that (a) is signed by the same manager, (b) carries
// type "sudo", and (c) belongs to the SAME user as the access token. A sudo
// token therefore cannot be replayed by a different account, and an ordinary
// access token alone can never satisfy it — the user must have proven knowledge
// of a current TOTP code within the sudo TTL (default 15 minutes).
func SudoMiddleware(jwtMgr *jwt.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader(SudoHeader)
		if token == "" {
			response.Respond(c, http.StatusForbidden, "sudo verification required", nil)
			c.Abort()
			return
		}
		claims, err := jwtMgr.Verify(token)
		if err != nil {
			response.Respond(c, http.StatusForbidden, "sudo verification required", nil)
			c.Abort()
			return
		}
		if claims.Type != jwt.TokenTypeSudo {
			response.Respond(c, http.StatusForbidden, "sudo verification required", nil)
			c.Abort()
			return
		}
		v, ok := c.Get(CtxUserID)
		uid, isUint := v.(uint)
		if !ok || !isUint || claims.UserID != uid {
			// The sudo token belongs to a different user than the access
			// token — reject rather than let one session elevate another.
			response.Respond(c, http.StatusForbidden, "sudo verification required", nil)
			c.Abort()
			return
		}
		if claims.ExpiresAt != nil {
			c.Set(CtxSudoUntil, claims.ExpiresAt.UTC())
		}
		c.Next()
	}
}

// SudoUntil returns the expiry of the verified sudo token (zero time when the
// claims carried none — e.g. a legacy token). Handlers rarely need it; it is
// exposed for audit logging.
func SudoUntil(c *gin.Context) time.Time {
	v, ok := c.Get(CtxSudoUntil)
	if !ok {
		return time.Time{}
	}
	t, ok := v.(time.Time)
	if !ok {
		return time.Time{}
	}
	return t
}
