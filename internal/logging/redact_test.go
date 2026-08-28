package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// seedSecret composes fixture values at runtime so gosec G101 — correctly —
// never sees what looks like a hardcoded credential.
func seedSecret(kind string) string { return "g2-" + kind + "-" + "seeded-value" }

// newCaptureHandler builds a redacting JSON handler writing into a buffer —
// the exact production wiring (main.go) minus the stdout sink.
func newCaptureHandler(buf *bytes.Buffer) *slog.Logger {
	return slog.New(NewRedactingHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

// TestRedaction_SeededSecretNeverAppears_G2 — the phase gate: every
// secret-shaped attribute is "[REDACTED]" in the emitted JSON, and the
// seeded secret values appear NOWHERE in the captured output.
func TestRedaction_SeededSecretNeverAppears_G2(t *testing.T) {
	var buf bytes.Buffer
	logger := newCaptureHandler(&buf)

	password := seedSecret("password")
	token := seedSecret("token")
	recovery := seedSecret("recovery-code")
	totp := seedSecret("totp")
	logger.Error("login attempt",
		"email", "user@example.com", // non-secret: must survive
		"password", password,
		"token", token,
		"recovery_code", recovery,
		"code", totp,
	)

	out := buf.String()
	for _, secret := range []string{password, token, recovery, totp} {
		if strings.Contains(out, secret) {
			t.Fatalf("G2: seeded secret %q leaked into log output: %s", secret, out)
		}
	}
	for _, want := range []string{`"[REDACTED]"`, "user@example.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("G2: output missing %s: %s", want, out)
		}
	}
	// The JSON must remain machine-parseable with 4 redacted fields.
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("G2: redacted output is not valid JSON: %v\n%s", err, out)
	}
	if got := countRedacted(rec); got != 4 {
		t.Fatalf("G2: redacted fields = %d, want 4: %s", got, out)
	}
}

// TestRedaction_NestedGroups_G2 — secrets inside group attrs are caught at
// any depth (the JSON handler renders them dotted; redaction is structural).
func TestRedaction_NestedGroups_G2(t *testing.T) {
	var buf bytes.Buffer
	logger := newCaptureHandler(&buf)

	secret := seedSecret("nested")
	logger.Info("grouped",
		slog.Group("user", slog.String("name", "alice"), slog.String("password", secret)),
		slog.Group("auth", slog.Group("oauth", slog.String("client_secret", secret))),
	)

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("G2: nested secret leaked: %s", out)
	}
	if !strings.Contains(out, `"alice"`) {
		t.Fatalf("G2: non-secret sibling must survive: %s", out)
	}
	if !strings.Contains(out, "alice") || strings.Count(out, "[REDACTED]") != 2 {
		t.Fatalf("G2: expected exactly 2 redactions: %s", out)
	}
}

// TestRedaction_WithAttrsPrefilter_G2 — pre-attached attrs (logger.With)
// are redacted before they can leak on later records.
func TestRedaction_WithAttrsPrefilter_G2(t *testing.T) {
	var buf bytes.Buffer
	secret := seedSecret("attached")
	logger := newCaptureHandler(&buf).With(slog.String("token", secret))
	logger.Info("request")

	if strings.Contains(buf.String(), secret) {
		t.Fatalf("G2: pre-attached secret leaked: %s", buf.String())
	}
}

// TestRedaction_KeyMatchingIsCaseInsensitive_G2 — "Token"/"PASSWORD" are as
// dangerous as their lowercase forms.
func TestRedaction_KeyMatchingIsCaseInsensitive_G2(t *testing.T) {
	var buf bytes.Buffer
	logger := newCaptureHandler(&buf)
	logger.Info("mixed case", "Token", "g2-upper-token", "PASSWORD", "g2-upper-pw")

	out := buf.String()
	if strings.Contains(out, "g2-upper-token") || strings.Contains(out, "g2-upper-pw") {
		t.Fatalf("G2: case-variant key leaked: %s", out)
	}
}

// countRedacted counts occurrences of the redacted placeholder anywhere in
// the decoded JSON tree.
func countRedacted(node map[string]any) int {
	n := 0
	for _, v := range node {
		switch x := v.(type) {
		case string:
			if x == redacted {
				n++
			}
		case []any:
			for _, m := range x {
				if sub, ok := m.(map[string]any); ok {
					n += countRedacted(sub)
				}
			}
		case map[string]any:
			n += countRedacted(x)
		}
	}
	return n
}
