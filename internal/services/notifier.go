package services

import (
	"log"
)

// ConsoleNotifier is the default Notifier implementation: it logs messages to
// stdout instead of sending real email/SMS. Swap for an SMTP-backed notifier
// in production by implementing the Notifier interface.
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
