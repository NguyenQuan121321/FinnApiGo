package metrics

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// BearerAuth wraps a handler with an optional bearer-token gate (X1). An
// empty token keeps the handler open — the token is optional; binding the
// listener to an internal address is the primary control. The comparison is
// constant-time so scrape-token timing is not a side channel.
func BearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			const prefix = "Bearer "
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, prefix) ||
				subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(token)) != 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
