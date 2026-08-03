package services

import (
	"log"
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

func (n *ConsoleNotifier) SendOTP(to, code, purpose string) error {
	log.Printf("[MAIL] to=%s from=%s subject=Your %s code  CODE=%s", to, n.From, purpose, code)
	return nil
}

func (n *ConsoleNotifier) SendPasswordReset(to, resetToken string) error {
	log.Printf("[MAIL] to=%s from=%s subject=Password reset  RESET_TOKEN=%s", to, n.From, resetToken)
	return nil
}

// SendEmailVerification delivers the email-verification JWT so the user must
// prove inbox control to self-verify (§1.1).
func (n *ConsoleNotifier) SendEmailVerification(to, verifyToken string) error {
	log.Printf("[MAIL] to=%s from=%s subject=Verify your email  VERIFY_TOKEN=%s", to, n.From, verifyToken)
	return nil
}
