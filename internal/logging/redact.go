// Package logging provides slog handler composition for the production
// logging guarantees (G2): known secret-shaped attribute values are replaced
// with "[REDACTED]" BEFORE records reach the sink. It is defense-in-depth —
// the codebase must never log secrets in the first place (the request logger
// hand-picks safe fields; the console notifier refuses live tokens in
// release mode) — this handler makes the guarantee structural rather than
// call-site discipline.
package logging

import (
	"context"
	"log/slog"
	"strings"
)

// redacted is the value substituted for every secret-shaped attribute.
const redacted = "[REDACTED]"

// secretKeys are the attribute keys whose values must never reach the logs.
// Matching is exact and case-insensitive on the attribute's RELATIVE key:
// group members keep their relative key inside the attr tree (the sink
// handler applies group prefixes at render time), so a "password" attr
// inside a "user" group is still caught.
//
// "code" is deliberately included — TOTP/recovery codes are the most likely
// accidental log payload — at the cost of also redacting a hypothetical
// benign "code" attribute. Err on the side of silence.
var secretKeys = map[string]struct{}{
	"authorization": {},
	"access_token":  {},
	"refresh_token": {},
	"id_token":      {},
	"bearer":        {},
	"password":      {},
	"passwd":        {},
	"pwd":           {},
	"secret":        {},
	"client_secret": {},
	"secret_key":    {},
	"private_key":   {},
	"api_key":       {},
	"apikey":        {},
	"token":         {},
	"jwt":           {},
	"code":          {},
	"totp":          {},
	"totp_code":     {},
	"recovery_code": {},
	"cookie":        {},
	"set_cookie":    {},
	"credentials":   {},
	"dsn":           {},
}

// RedactingHandler wraps any slog.Handler and strips secret-shaped values.
type RedactingHandler struct {
	next slog.Handler
}

// NewRedactingHandler wraps next.
func NewRedactingHandler(next slog.Handler) *RedactingHandler {
	return &RedactingHandler{next: next}
}

func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

// Handle rebuilds the record with redacted attrs — slog.Record cannot be
// mutated in place, and delegating the original would leak the secrets.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, clean)
}

// WithAttrs redacts pre-attached attrs too — logger.With("password", p)
// must not leak on later records.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		clean[i] = redactAttr(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(clean)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{next: h.next.WithGroup(name)}
}

// redactAttr replaces the value when the key is secret-shaped; group values
// are recursed so nested secrets are caught at any depth.
func redactAttr(a slog.Attr) slog.Attr {
	if _, hit := secretKeys[strings.ToLower(a.Key)]; hit {
		return slog.String(a.Key, redacted)
	}
	if a.Value.Kind() == slog.KindGroup {
		members := a.Value.Group()
		clean := make([]any, 0, len(members))
		for _, m := range members {
			clean = append(clean, redactAttr(m))
		}
		return slog.Group(a.Key, clean...)
	}
	return a
}
