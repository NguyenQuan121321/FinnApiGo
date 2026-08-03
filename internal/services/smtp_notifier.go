package services

import (
	"fmt"
	"net/smtp"
	"strings"
)

// SMTPNotifier is a real Notifier backed by net/smtp (§1.2). It is selected
// at startup when SMTP_HOST is set; otherwise ConsoleNotifier is used.
//
// Auth is PLAIN over TLS — the standard submission-port (587) flow. If your
// provider needs LOGIN auth or a different port, extend here. This is
// deliberately dependency-free (stdlib only) so it compiles anywhere.
type SMTPNotifier struct {
	host     string
	port     string
	user     string
	password string
	from     string
}

// NewSMTPNotifier constructs the notifier from SMTPConfig.
func NewSMTPNotifier(host, port, user, password, from string) *SMTPNotifier {
	return &SMTPNotifier{host: host, port: port, user: user, password: password, from: from}
}

// Enabled reports whether the notifier has enough config to send. Used by the
// startup selector to log a clear warning when partially configured.
func (n *SMTPNotifier) Enabled() bool {
	return n.host != "" && n.from != ""
}

// send is the shared delivery path: builds an RFC 822 message and sends it.
func (n *SMTPNotifier) send(to, subject, body string) error {
	if !n.Enabled() {
		return fmt.Errorf("smtp notifier not configured")
	}
	addr := n.host + ":" + n.port
	msg := strings.Join([]string{
		"From: " + n.from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	var auth smtp.Auth
	if n.user != "" {
		auth = smtp.PlainAuth("", n.user, n.password, n.host)
	}
	return smtp.SendMail(addr, auth, n.from, []string{to}, []byte(msg))
}

func (n *SMTPNotifier) SendOTP(to, code, purpose string) error {
	return n.send(to, "Your "+purpose+" code",
		"Your verification code is: "+code+"\n\nIt expires in a few minutes. If you did not request it, ignore this email.")
}

func (n *SMTPNotifier) SendPasswordReset(to, resetToken string) error {
	return n.send(to, "Password reset",
		"Use this token to reset your password: "+resetToken+"\n\nIf you did not request a reset, ignore this email.")
}

func (n *SMTPNotifier) SendEmailVerification(to, verifyToken string) error {
	return n.send(to, "Verify your email",
		"Use this token to verify your email: "+verifyToken+"\n\nIf you did not create an account, ignore this email.")
}
