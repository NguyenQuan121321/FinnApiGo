package services

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
)

// errConsoleTokensSuppressed is returned when the ConsoleNotifier refuses to
// operate: it would log live password-reset / verification tokens to stdout,
// which must not happen outside development.
var errConsoleTokensSuppressed = errors.New("console notifier suppressed in release mode (would log auth tokens); configure SMTP or set ALLOW_TOKEN_CONSOLE=true")

// ConsoleNotifier is the default Notifier implementation: it logs messages to
// stdout instead of sending real email/SMS. Swap for an SMTP-backed notifier
// in production by implementing the Notifier interface.
//
// §1.1 — SendEmailVerification was added so registration no longer needs to
// return the verification token in the API response; it is delivered here,
// exactly like the password-reset token.
//
// A8 — logging LIVE auth tokens is a development convenience only. In
// GIN_MODE=release the notifier refuses to deliver unless the operator
// explicitly opts in with ALLOW_TOKEN_CONSOLE=true (e.g. dry-runs); sends
// then fail loudly rather than silently writing reset tokens to stdout,
// where they land in container logs, aggregators, and backups.
type ConsoleNotifier struct {
	From   string
	refuse bool
}

func NewConsoleNotifier(from string) *ConsoleNotifier {
	release := strings.EqualFold(os.Getenv("GIN_MODE"), "release")
	allowed := strings.EqualFold(os.Getenv("ALLOW_TOKEN_CONSOLE"), "true")
	n := &ConsoleNotifier{From: from}
	if release && !allowed {
		n.refuse = true
		slog.Error("console notifier disabled: GIN_MODE=release and ALLOW_TOKEN_CONSOLE is not true — " +
			"auth emails will fail until SMTP is configured")
	}
	return n
}

func (n *ConsoleNotifier) SendPasswordReset(ctx context.Context, to, resetToken string) error {
	if n.refuse {
		return errConsoleTokensSuppressed
	}
	slog.Info("[MAIL]", "to", to, "from", n.From, "subject", "Password reset", "reset_token", resetToken)
	return nil
}

// SendEmailVerification delivers the email-verification JWT so the user must
// prove inbox control to self-verify (§1.1).
func (n *ConsoleNotifier) SendEmailVerification(ctx context.Context, to, verifyToken string) error {
	if n.refuse {
		return errConsoleTokensSuppressed
	}
	slog.Info("[MAIL]", "to", to, "from", n.From, "subject", "Verify your email", "verify_token", verifyToken)
	return nil
}

// SendNewLoginAlert logs the transparency alert (no secrets involved — safe
// in every mode; the refuse flag gates only live-token delivery).
func (n *ConsoleNotifier) SendNewLoginAlert(ctx context.Context, to, ip, deviceName string) error {
	slog.Info("[MAIL]", "to", to, "from", n.From, "subject", "New sign-in to your account",
		"ip", ip, "device", deviceName)
	return nil
}

// SendDuplicateRegisterAlert logs an attempted duplicate registration alert (P0.1).
func (n *ConsoleNotifier) SendDuplicateRegisterAlert(ctx context.Context, to string) error {
	slog.Info("[MAIL]", "to", to, "from", n.From, "subject", "Security alert: duplicate registration attempt")
	return nil
}

// SendSecurityAlert logs generic security events (P0.3 / P1.1 / P1.2).
func (n *ConsoleNotifier) SendSecurityAlert(ctx context.Context, to, event, detail string) error {
	slog.Info("[MAIL]", "to", to, "from", n.From, "subject", event, "detail", detail)
	return nil
}

var _ Notifier = (*ConsoleNotifier)(nil)
