//go:build integration && linux

package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/go-sql-driver/mysql"
)

// Build and launch cmd/server itself, in release mode, against the task-owned
// migrated DB/Redis. No route/service/container wiring is replaced with a fake.
func TestF03ActualServerAdmissionAndStartup(t *testing.T) {
	db, dsn := f03DB(t)
	cfg, err := mysql.ParseDSN(dsn)
	mutationMust(t, err)
	dir := t.TempDir()
	binary := filepath.Join(dir, "f03-server")
	build := exec.Command("go", "build", "-race", "-o", binary, "../../cmd/server")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("server build: %v: %s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	mutationMust(t, err)
	port := strings.Split(listener.Addr().String(), ":")[1]
	mutationMust(t, listener.Close())
	key := func(label string) string {
		b := sha256.Sum256([]byte("F03 actual server synthetic " + label))
		return base64.StdEncoding.EncodeToString(b[:])
	}
	recovery := sha256.Sum256([]byte("F03 separate actual-server recovery"))
	signing, _ := json.Marshal(map[string]string{"f03": key("audit")})
	env := []string{"PATH=" + os.Getenv("PATH"), "GIN_MODE=release", "SERVER_PORT=" + port, "DB_HOST=127.0.0.1", "DB_PORT=3306", "DB_USER=" + cfg.User, "DB_PASSWORD=" + cfg.Passwd, "DB_NAME=" + cfg.DBName, "MIGRATE_AUTO=false", "RUN_JOBS=false", "JWT_SECRET=" + key("jwt"), "JWT_KEY_ID=f03-jwt", "IDENTITY_STATE_SECRET=" + key("state"), "IDENTITY_STATE_KEY_ID=f03-state", "RECOVERY_CODE_KEY=" + hex.EncodeToString(recovery[:]), "AUDIT_KEY_ID=f03", "AUDIT_SIGNING_KEYS=" + string(signing), "AUDIT_CHECKPOINT_KEY=" + key("checkpoint"), "REDIS_URL=" + os.Getenv("TEST_REDIS_URL"), "LOGIN_NOTIFY_NEW_IP=false", "METRICS_ADDR=127.0.0.1:0", "BCRYPT_COST=4"}
	// Missing/default signing material must stop the actual production process.
	for _, invalid := range []string{"", `{"f03":"YXVkaXQtaGFzaC1jaGFpbi1kZWZhdWx0LXNlY3JldC0zMmI="}`} {
		cmd := exec.Command(binary)
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, env...), "AUDIT_SIGNING_KEYS="+invalid)
		if err := cmd.Run(); err == nil {
			t.Fatal("production process accepted invalid audit keys")
		}
	}
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	mutationMust(t, err)
	defer func() { _ = logFile.Close() }()
	cmd := exec.Command(binary)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	mutationMust(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	client := &http.Client{Timeout: time.Second}
	base := "http://127.0.0.1:" + port
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("actual release server failed to become healthy; inspect isolated test server.log")
	}
	password := "F03ActualServerPassword42!"
	hashed, err := hash.HashPassword(password, hash.MinCost)
	mutationMust(t, err)
	user := &models.User{TenantID: "default", Username: "f03-http", Email: "f03-http@example.invalid", Password: hashed, IsActive: true, IsEmailVerified: true}
	mutationMust(t, repositories.NewUserRepository(db).Create(context.Background(), user))
	login := func() (*http.Response, []byte) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"email": user.Email, "password": password})
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/auth/login", bytes.NewReader(body))
		mutationMust(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-ID", "attacker-header")
		resp, err := client.Do(req)
		mutationMust(t, err)
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		mutationMust(t, err)
		_ = resp.Body.Close()
		return resp, raw
	}
	resp, raw := login()
	if resp.StatusCode != 200 || !bytes.Contains(raw, []byte("accessToken")) {
		t.Fatalf("actual login status=%d", resp.StatusCode)
	}
	rid := resp.Header.Get("X-Request-ID")
	if rid == "attacker-header" || len(rid) != 36 {
		t.Fatal("untrusted request correlation")
	}
	var event models.AuditLog
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if db.Where("event = ? AND request_id = ?", "login", rid).First(&event).Error == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if event.EventID == "" || event.ActorID != user.ID || event.ActorKind != "authenticated" || event.TenantID != "default" || event.RecordHash == "" {
		t.Fatal("cmd/server -> AsyncAuditWriter -> signed repository wiring missing")
	}
	var before int64
	mutationMust(t, db.Model(&models.Session{}).Count(&before).Error)
	mutationMust(t, db.Exec("CREATE TRIGGER f03_http_reject BEFORE INSERT ON audit_outboxes FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='F03 synthetic admission outage'").Error)
	defer func() { mutationMust(t, db.Exec("DROP TRIGGER IF EXISTS f03_http_reject").Error) }()
	resp, raw = login()
	if resp.StatusCode != 503 || bytes.Contains(raw, []byte("accessToken")) || !bytes.Contains(raw, []byte("durable audit unavailable")) {
		t.Fatalf("actual failed-admission response=%d", resp.StatusCode)
	}
	var after int64
	mutationMust(t, db.Model(&models.Session{}).Count(&after).Error)
	if before != after {
		t.Fatal("HTTP failure left an issued session")
	}
	t.Log("actual release cmd/server: missing/default audit keys reject startup; healthy async signed login; injected outbox failure returns HTTP503 without tokens/session")
}
