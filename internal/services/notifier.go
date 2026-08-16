package services

import (
	"log/slog"
)

// ConsoleNotifier is the default Notifier implementation: it logs messages to
// stdout instead of sending real email/SMS. Swap for an SMTP-backed notifier
// in production by implementing the Notifier interface.
//
// §1.1 — SendEmailVerification was added so registration no longer needs to
// return the verification token in the API response; it is delivered here
// exactly like the password-reset token.
type ConsoleNotifier struct {
	From string
}

func NewConsoleNotifier(from string) *ConsoleNotifier {
	return &ConsoleNotifier{From: from}
}

func (n *ConsoleNotifier) SendPasswordReset(to, resetToken string) error {
	slog.Info("[MAIL]", "to", to, "from", n.From, "subject", "Password reset", "reset_token", resetToken)
	return nil
}

// SendEmailVerification delivers the email-verification JWT so the user must
// prove inbox control to self-verify (§1.1).
func (n *ConsoleNotifier) SendEmailVerification(to, verifyToken string) error {
	slog.Info("[MAIL]", "to", to, "from", n.From, "subject", "Verify your email", "verify_token", verifyToken)
	return nil
}
