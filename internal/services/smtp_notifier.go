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
	// smtpTotalTimeout bounds the WHOLE delivery — the per-command deadline
	// alone lets a relay that accepts then stalls each of the ~7 SMTP steps
	// pin a request goroutine for ~70s. One overall cap keeps the worst case
	// predictable regardless of how many commands the relay dribbles out.
	smtpTotalTimeout = 45 * time.Second
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

// validEnvelopeAddr enforces RFC 5321-safe envelope addresses: exactly one @,
// no CR/LF/whitespace/control characters anywhere. It is the boundary that
// makes SMTP command injection impossible (gosec G707) regardless of what the
// caller passes.
func validEnvelopeAddr(addr string) error {
	if addr == "" || len(addr) > 254 {
		return fmt.Errorf("invalid envelope address length")
	}
	if strings.Count(addr, "@") != 1 {
		return fmt.Errorf("envelope address must contain exactly one @")
	}
	for _, r := range addr {
		if r <= 32 || r == 127 { // controls, space, CR, LF, TAB
			return fmt.Errorf("envelope address contains forbidden character %#U", r)
		}
	}
	return nil
}

// validHeaderValue rejects line breaks in a RFC 822 header value. Header
// fields must occupy exactly one line; accepting CR or LF here would allow a
// caller to inject additional MIME or SMTP headers into the DATA stream.
func validHeaderValue(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("header value contains a line break")
	}
	return nil
}

// safeMailDisplayValue keeps request-derived values on one readable text line
// before they are interpolated into an email body. This prevents a malicious
// User-Agent or similar value from creating spoofed header-like content.
func safeMailDisplayValue(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.Join(strings.Fields(value), " ")
}

// safeMailIP returns a canonical IP address or a non-sensitive placeholder.
// It prevents an untrusted forwarded-header string from reaching an email.
func safeMailIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "Unknown"
	}
	return parsed.String()
}

// send is the shared delivery path: builds an RFC 822 message and sends it.
func (n *SMTPNotifier) send(ctx context.Context, to, subject, body string) error {
	if !n.Enabled() {
		return fmt.Errorf("smtp notifier not configured")
	}
	// G707 — the recipient originates from user input (registration /
	// recovery email). SMTP command injection (CR/LF smuggling into the RCPT
	// or DATA wire) is rejected at the boundary instead of trusting callers.
	if err := validEnvelopeAddr(to); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if err := validEnvelopeAddr(n.from); err != nil {
		return fmt.Errorf("smtp sender: %w", err)
	}
	if err := validHeaderValue(subject); err != nil {
		return fmt.Errorf("smtp subject: %w", err)
	}
	// Overall delivery cap (on top of the per-command deadlines below).
	ctx, cancel := context.WithTimeout(ctx, smtpTotalTimeout)
	defer cancel()
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
	if err := cl.Rcpt(to); err != nil { // #nosec G707 -- recipient validated by validEnvelopeAddr above
		return fmt.Errorf("smtp RCPT: %w", err)
	}
	deadline()
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	// codeql[go/email-injection] -- header values are validated and the only
	// request-derived body fields are canonicalized before a fixed text template.
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

// SendNewLoginAlert delivers the transparency notification for a sign-in from
// a previously unseen IP. The message intentionally carries no tokens or
// links — it is informational (and unactionable links train users to click
// email links).
func (n *SMTPNotifier) SendNewLoginAlert(ctx context.Context, to, ip, deviceName string) error {
	ip = safeMailIP(ip)
	deviceName = safeMailDisplayValue(deviceName)
	body := "A new sign-in to your account was detected.\n\n" +
		"IP address: " + ip + "\n" +
		"Device:     " + deviceName + "\n" +
		"Time (UTC): " + time.Now().UTC().Format(time.RFC3339) + "\n\n" +
		"If this was you, no action is needed. If you do not recognize this " +
		"sign-in, change your password immediately and revoke unknown sessions."
	return n.send(ctx, to, "New sign-in to your account", body)
}
