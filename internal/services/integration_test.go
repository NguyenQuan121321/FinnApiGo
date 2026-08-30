//go:build integration

// S3 — concurrent refresh-rotation against a REAL MySQL: N goroutines present
// the same valid refresh token simultaneously; exactly one wins the CAS
// rotation (C1) and the losers are rejected as token reuse with an audit
// trail. Extends v2 C1's unit-level proof to a real database under real
// concurrency (still without -race locally — that is CI's job).
package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
)

// TestRefresh_ConcurrentRotationExactlyOneWinner_S3 — the S3 gate.
func TestRefresh_ConcurrentRotationExactlyOneWinner_S3(t *testing.T) {
	raw := os.Getenv("TEST_MYSQL_DSN")
	if raw == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping MySQL integration test")
	}
	dsn := raw
	if !strings.Contains(dsn, "parseTime") {
		if strings.Contains(dsn, "?") {
			dsn += "&parseTime=True&loc=UTC"
		} else {
			dsn += "?parseTime=True&loc=UTC"
		}
	}
	if err := database.RunMigrations(raw); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		t.Fatalf("connect mysql: %v", err)
	}
	sqlDB, _ := db.DB()
	defer func() { _ = sqlDB.Close() }()
	ctx := context.Background()

	// --- build the real dependency graph on the real DB ---
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewRefreshTokenRepository(db)
	usedTokenRepo := repositories.NewUsedTokenRepository(db)
	baseAuditRepo := repositories.NewAuditRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	auditWriter := NewAsyncAuditWriter(baseAuditRepo, baseAuditRepo, config.AuditConfig{BufferSize: 256, FlushBatch: 32})
	// Closed explicitly below to flush buffered entries before the audit
	// count assertion — Close is NOT idempotent (channel close).

	kv := store.NewInMemoryStore(0)
	defer kv.Close()
	jwtMgr := jwt.NewJWTManager("s3-integration-secret-value", "s3-test")
	authSvc := NewAuthService(
		userRepo, tokenRepo, usedTokenRepo, auditWriter, kv,
		jwtMgr, config.AuthConfig{}, config.RateLimitConfig{},
		config.JWTConfig{Issuer: "s3-test", AccessTTL: time.Minute, RefreshTTL: time.Hour},
		NewConsoleNotifier("s3-test@local"), nil, nil, totpRepo, nil,
	)

	// --- seed: one user, one valid refresh token ---
	stamp := time.Now().UnixNano()
	u := &models.User{
		Username: fmt.Sprintf("s3user-%d", stamp),
		Email:    fmt.Sprintf("s3-%d@example.com", stamp),
		Password: "hash", Role: models.RoleUser, IsActive: true,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Where("user_id = ?", u.ID).Delete(&models.RefreshToken{})
		db.Where("user_id = ?", u.ID).Delete(&models.AuditLog{})
		db.Where("username = ?", u.Username).Delete(&models.User{})
	})

	refreshToken := fmt.Sprintf("s3-opaque-%d", stamp)
	now := time.Now()
	if err := tokenRepo.Create(ctx, &models.RefreshToken{
		UserID:       u.ID,
		TokenHash:    hash.HashToken(refreshToken),
		ExpiresAt:    now.Add(time.Hour),
		LastActiveAt: now,
		CreatedAt:    now,
	}); err != nil {
		t.Fatal(err)
	}

	// --- fire N concurrent refreshes of the SAME token ---
	const n = 16
	var successes, failures atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := authSvc.Refresh(ctx, refreshToken, fmt.Sprintf("10.0.0.%d", i%250), "s3-integration")
			if err == nil {
				successes.Add(1)
				return
			}
			if errors.Is(err, ErrInvalidToken) {
				failures.Add(1)
				return
			}
			t.Errorf("unexpected error from contender %d: %v", i, err)
		}(i)
	}
	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("S3: successes = %d, want exactly 1 (CAS rotation violated)", got)
	}
	if got := failures.Load(); got != n-1 {
		t.Fatalf("S3: failures = %d, want %d", got, n-1)
	}

	// Losers are token-reuse events: revoke-all + audited (theft response).
	auditWriter.Close()
	time.Sleep(100 * time.Millisecond)
	var reuseCount int64
	db.Model(&models.AuditLog{}).
		Where("user_id = ? AND event = ?", u.ID, models.AuditEventTokenReuse).
		Count(&reuseCount)
	if reuseCount == 0 {
		t.Fatal("S3: losing contenders must record token_reuse audit events")
	}
	t.Logf("S3: %d concurrent refreshes → 1 winner, %d reuse-audited losers", n, reuseCount)
}

// TestIntegrationEnvironmentGuard makes silent integration skips impossible:
// in CI the service env MUST be provided — a missing variable fails the job
// instead of letting every integration test skip its way to green (the
// apidrift "the check itself is broken" doctrine applied to integration).
func TestIntegrationEnvironmentGuard(t *testing.T) {
	if os.Getenv("TEST_MYSQL_DSN") == "" || os.Getenv("TEST_REDIS_URL") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI must provide TEST_MYSQL_DSN and TEST_REDIS_URL — integration tests silently skipping to green is forbidden")
		}
		t.Skip("integration env not set (local run)")
	}
}
