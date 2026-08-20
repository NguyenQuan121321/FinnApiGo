package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTP delivery timeouts (A2). The dial timeout bounds connection buildup;
// the per-command deadline bounds each SMTP exchange (EHLO/STARTTLS/AUTH/
// MAIL/RCPT/DATA) so a wedged relay cannot pin request goroutines forever.
const (
	smtpDialTimeout = 10 * time.Second
	smtpCmdTimeout  = 10 * time.Second
)

// SMTPNotifier is a real Notifier backed by net/smtp (§1.2). It is selected
// at startup when SMTP_HOST is set; otherwise ConsoleNotifier is used.
//
// Transport security (A2): port 465 uses implicit TLS; every other port MUST
// offer STARTTLS — credentials are never sent over a plaintext channel, so a
// relay without TLS support is a hard error rather than a silent downgrade.
// The whole delivery honors the caller's context plus explicit deadlines.
type SMTPNotifier struct {
	host     string
	port     string
	user     string
	password string
	from     string
	// implicitTLS selects the SMTPS (465) flow: TLS before the SMTP greeting.
	// Derived from port in the constructor; a field so tests can exercise
	// the branch against an ephemeral port.
	implicitTLS bool
}

// NewSMTPNotifier constructs the notifier from SMTPConfig.
func NewSMTPNotifier(host, port, user, password, from string) *SMTPNotifier {
	return &SMTPNotifier{host: host, port: port, user: user, password: password, from: from, implicitTLS: port == "465"}
}

// Enabled reports whether the notifier has enough config to send. Used by the
// startup selector to log a clear warning when partially configured.
func (n *SMTPNotifier) Enabled() bool {
	return n.host != "" && n.from != ""
}

// send is the shared delivery path: builds an RFC 822 message and sends it.
func (n *SMTPNotifier) send(ctx context.Context, to, subject, body string) error {
	if !n.Enabled() {
		return fmt.Errorf("smtp notifier not configured")
	}
	addr := net.JoinHostPort(n.host, n.port)
	msg := strings.Join([]string{
		"From: " + n.from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	d := net.Dialer{Timeout: smtpDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	// deadline applies to every command phase below; tls.Conn propagates
	// SetDeadline to the underlying connection.
	deadline := func() { _ = conn.SetDeadline(time.Now().Add(smtpCmdTimeout)) }

	if n.implicitTLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: n.host})
		deadline()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("smtp implicit TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	cl, err := smtp.NewClient(conn, n.host)
	if err != nil {
		return fmt.Errorf("smtp client init: %w", err)
	}
	defer func() { _ = cl.Close() }()

	if !n.implicitTLS {
		deadline()
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp server %s:%s offers no STARTTLS — refusing to send mail credentials in plaintext", n.host, n.port)
		}
		if err := cl.StartTLS(&tls.Config{ServerName: n.host}); err != nil {
			return fmt.Errorf("smtp STARTTLS: %w", err)
		}
	}

	if n.user != "" {
		deadline()
		if err := cl.Auth(smtp.PlainAuth("", n.user, n.password, n.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	deadline()
	if err := cl.Mail(n.from); err != nil {
		return fmt.Errorf("smtp MAIL: %w", err)
	}
	deadline()
	if err := cl.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT: %w", err)
	}
	deadline()
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close body: %w", err)
	}
	deadline()
	return cl.Quit()
}

func (n *SMTPNotifier) SendPasswordReset(ctx context.Context, to, resetToken string) error {
	return n.send(ctx, to, "Password reset",
		"Use this token to reset your password: "+resetToken+"\n\nIf you did not request a reset, ignore this email.")
}

func (n *SMTPNotifier) SendEmailVerification(ctx context.Context, to, verifyToken string) error {
	return n.send(ctx, to, "Verify your email",
		"Use this token to verify your email: "+verifyToken+"\n\nIf you did not create an account, ignore this email.")
}
