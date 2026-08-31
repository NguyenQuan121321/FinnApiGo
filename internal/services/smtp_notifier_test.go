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

func TestSMTPNotifier_RejectsSubjectHeaderInjection(t *testing.T) {
	n := NewSMTPNotifier("127.0.0.1", "1", "user", "pass", "from@example.com")
	err := n.send(context.Background(), "to@example.com", "Hello\r\nBcc: attacker@example.com", "body")
	if err == nil {
		t.Fatal("subject containing a line break must be rejected")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("error should identify the subject validation failure, got: %v", err)
	}
}
