package services

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSMTPServer accepts one connection and speaks the minimal ESMTP
// greeting. withStartTLS controls whether STARTTLS is advertised. It serves
// exactly one conn then stops — enough for the refusal/handshake assertions.
func fakeSMTPServer(t *testing.T, advertiseStartTLS bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// SMTPS clients (implicit TLS) speak first with a TLS handshake; the
		// plaintext greeting bytes make that fail fast.
		_, _ = conn.Write([]byte("220 fake ESMTP ready\r\n"))
		r := bufio.NewReader(conn)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if strings.HasPrefix(strings.ToUpper(line), "EHLO") {
			ext := "250-fake.local\r\n250 SIZE 33554432\r\n"
			if advertiseStartTLS {
				ext = "250-fake.local\r\n250-STARTTLS\r\n250 SIZE 33554432\r\n"
			}
			_, _ = conn.Write([]byte(ext))
		}
		// Hold the conn open until the client gives up / test ends.
		time.Sleep(2 * time.Second)
	}()
	return ln.Addr().String()
}

// TestSMTPNotifier_RefusesPlaintextWithoutSTARTTLS_A2 — A2: a submission
// server that does not offer STARTTLS must be refused, never downgraded to
// plaintext credentials.
func TestSMTPNotifier_RefusesPlaintextWithoutSTARTTLS_A2(t *testing.T) {
	addr := fakeSMTPServer(t, false)
	host, port, _ := net.SplitHostPort(addr)
	n := NewSMTPNotifier(host, port, "user", "pass", "from@example.com")
	err := n.SendEmailVerification(context.Background(), "to@example.com", "tok")
	if err == nil {
		t.Fatal("delivery without STARTTLS must fail")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("error should name the STARTTLS refusal, got: %v", err)
	}
}

// TestSMTPNotifier_ImplicitTLSEngaged_A2 — A2: with the SMTPS (465) flow
// selected, the client must start a TLS handshake immediately — against a
// plaintext listener that handshake fails, proving TLS is actually attempted
// before any credentials could move.
func TestSMTPNotifier_ImplicitTLSEngaged_A2(t *testing.T) {
	addr := fakeSMTPServer(t, false)
	host, port, _ := net.SplitHostPort(addr)
	n := &SMTPNotifier{host: host, port: port, user: "user", password: "pass",
		from: "from@example.com", implicitTLS: true}
	err := n.SendPasswordReset(context.Background(), "to@example.com", "tok")
	if err == nil {
		t.Fatal("TLS handshake against a plaintext server must fail")
	}
	if !strings.Contains(err.Error(), "implicit TLS handshake") {
		t.Fatalf("error should come from the TLS handshake phase, got: %v", err)
	}
}

// TestSMTPNotifier_HonorsContext_A2 — A2: a pre-cancelled context must abort
// delivery at dial time instead of proceeding.
func TestSMTPNotifier_HonorsContext_A2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := NewSMTPNotifier("127.0.0.1", "1", "user", "pass", "from@example.com") // port 1: nothing there
	err := n.SendPasswordReset(ctx, "to@example.com", "tok")
	if err == nil {
		t.Fatal("cancelled context must fail delivery")
	}
	// Windows renders the wrapped context.Canceled as "operation was canceled".
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "cancel") {
		t.Fatalf("error should surface the context cancellation, got: %v", err)
	}
}

func TestSMTPNotifier_RejectsSubjectHeaderInjectionBeforeSMTPConnection(t *testing.T) {
	testCases := []string{
		"Hello\r\nBcc: attacker@example.com",
		"Hello\nBcc: attacker@example.com",
		"Hello\rBcc: attacker@example.com",
	}

	for _, subject := range testCases {
		t.Run("rejects line break", func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })

			connected := make(chan struct{}, 1)
			go func() {
				conn, err := ln.Accept()
				if err == nil {
					connected <- struct{}{}
					_ = conn.Close()
				}
			}()

			host, port, _ := net.SplitHostPort(ln.Addr().String())
			n := NewSMTPNotifier(host, port, "user", "pass", "from@example.com")
			err = n.send(context.Background(), "to@example.com", subject, "body")
			if err == nil || !strings.Contains(err.Error(), "smtp subject") {
				t.Fatalf("injected subject must be rejected, got: %v", err)
			}

			select {
			case <-connected:
				t.Fatal("notifier opened an SMTP connection after rejecting the subject")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

func TestSafeMailDisplayValue(t *testing.T) {
	if got := safeMailDisplayValue("Chrome\r\nBcc: attacker@example.com"); got != "Chrome Bcc: attacker@example.com" {
		t.Fatalf("safeMailDisplayValue() = %q", got)
	}
	if got := safeMailIP("not-an-ip\r\nBcc: attacker@example.com"); got != "Unknown" {
		t.Fatalf("safeMailIP() = %q, want Unknown", got)
	}
}

func TestSMTPNotifier_ValidationAndDisabled(t *testing.T) {
	ctx := context.Background()

	// 1. Port 465 constructor
	n465 := NewSMTPNotifier("smtp.example.com", "465", "user", "pass", "from@example.com")
	if !n465.implicitTLS {
		t.Fatal("expected implicitTLS to be true for port 465")
	}

	// 2. Enabled checks
	if !n465.Enabled() {
		t.Fatal("expected Enabled to be true")
	}
	nEmptyHost := NewSMTPNotifier("", "587", "user", "pass", "from@example.com")
	if nEmptyHost.Enabled() {
		t.Fatal("expected Enabled to be false for empty host")
	}
	nEmptyFrom := NewSMTPNotifier("smtp.example.com", "587", "user", "pass", "")
	if nEmptyFrom.Enabled() {
		t.Fatal("expected Enabled to be false for empty from")
	}

	// 3. Disabled notifier returns error across all methods
	disabled := &SMTPNotifier{}
	if err := disabled.SendPasswordReset(ctx, "to@example.com", "token"); err == nil {
		t.Fatal("expected error on disabled SendPasswordReset")
	}
	if err := disabled.SendEmailVerification(ctx, "to@example.com", "token"); err == nil {
		t.Fatal("expected error on disabled SendEmailVerification")
	}
	if err := disabled.SendNewLoginAlert(ctx, "to@example.com", "1.2.3.4", "Firefox"); err == nil {
		t.Fatal("expected error on disabled SendNewLoginAlert")
	}
	if err := disabled.SendDuplicateRegisterAlert(ctx, "to@example.com"); err == nil {
		t.Fatal("expected error on disabled SendDuplicateRegisterAlert")
	}
	if err := disabled.SendSecurityAlert(ctx, "to@example.com", "Suspicious Activity", "Details here"); err == nil {
		t.Fatal("expected error on disabled SendSecurityAlert")
	}

	// 4. validEnvelopeAddr checks
	if err := validEnvelopeAddr(""); err == nil {
		t.Fatal("expected error on empty addr")
	}
	if err := validEnvelopeAddr(strings.Repeat("a", 255)); err == nil {
		t.Fatal("expected error on too long addr")
	}
	if err := validEnvelopeAddr("no-at-sign"); err == nil {
		t.Fatal("expected error on no @")
	}
	if err := validEnvelopeAddr("two@at@sign"); err == nil {
		t.Fatal("expected error on multiple @")
	}
	if err := validEnvelopeAddr("with space@example.com"); err == nil {
		t.Fatal("expected error on whitespace in addr")
	}
	if err := validEnvelopeAddr("control\x00@example.com"); err == nil {
		t.Fatal("expected error on control char in addr")
	}
	if err := validEnvelopeAddr("del\x7f@example.com"); err == nil {
		t.Fatal("expected error on DEL char in addr")
	}
	if err := validEnvelopeAddr("valid@example.com"); err != nil {
		t.Fatalf("unexpected error on valid addr: %v", err)
	}

	// 5. validHeaderValue checks
	if err := validHeaderValue("Valid Subject"); err != nil {
		t.Fatalf("unexpected error on valid header: %v", err)
	}
	if err := validHeaderValue("Subject\nInjection"); err == nil {
		t.Fatal("expected error on header with newline")
	}

	// 6. safeMailIP with valid IPs
	if got := safeMailIP("127.0.0.1"); got != "127.0.0.1" {
		t.Fatalf("unexpected ip %q", got)
	}
	if got := safeMailIP("::1"); got != "::1" {
		t.Fatalf("unexpected ipv6 %q", got)
	}

	// 7. Invalid recipient or sender rejected in send
	activeBadSender := NewSMTPNotifier("127.0.0.1", "25", "", "", "bad-sender")
	if err := activeBadSender.SendPasswordReset(ctx, "good@example.com", "token"); err == nil || !strings.Contains(err.Error(), "smtp sender") {
		t.Fatalf("expected smtp sender error, got %v", err)
	}
	activeGoodSender := NewSMTPNotifier("127.0.0.1", "25", "", "", "good@example.com")
	if err := activeGoodSender.SendPasswordReset(ctx, "bad-recipient", "token"); err == nil || !strings.Contains(err.Error(), "smtp: ") {
		t.Fatalf("expected smtp recipient error, got %v", err)
	}
}
