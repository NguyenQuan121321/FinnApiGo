//go:build integration

// Integration tests against a REAL MySQL (T1). They are excluded from the
// default `go test ./...` run by the `integration` build tag and executed by
// the CI integration job (MySQL service container) and locally via:
//
//	TEST_MYSQL_DSN='test:testpw@tcp(127.0.0.1:3307)/finnapigo_test?multiStatements=true' \
//		go test -tags=integration ./internal/database/ -v -count=1
//
// The DSN must carry multiStatements=true for the golang-migrate MySQL driver.
package database

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/migrations"
)

func testEnv(key string) string { return os.Getenv(key) }

// normalizedDSN guarantees the driver params the app itself always uses:
// multiStatements for golang-migrate, parseTime so DATETIME columns scan
// into time.Time. TEST_MYSQL_DSN may be a bare DSN.
func normalizedDSN(raw string) string {
	missing := ""
	if !strings.Contains(raw, "multiStatements") {
		missing += "&multiStatements=true"
	}
	if !strings.Contains(raw, "parseTime") {
		missing += "&parseTime=True"
	}
	if !strings.Contains(raw, "loc=") {
		missing += "&loc=UTC"
	}
	if missing == "" {
		return raw
	}
	sep := "&"
	if !strings.Contains(raw, "?") {
		sep = "?"
	}
	return raw + sep + missing[1:]
}

// integrationDSN returns the DSN for the MySQL under test, or skips the test.
func integrationDSN(t *testing.T) string {
	t.Helper()
	dsn := testEnv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping MySQL integration test")
	}
	return normalizedDSN(dsn)
}

func openIntegrationDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormlogger.Discard,
	})
	if err != nil {
		t.Fatalf("connect mysql: %v", err)
	}
	return db
}

// TestMigrationUpDown_T1 — R1's manual verification, automated: the embedded
// migration set applies cleanly (up), reports a clean (non-dirty) version,
// rolls all the way back (down), and reapplies. Catches broken down-scripts
// and dirty-state regressions before a deploy does.
func TestMigrationUpDown_T1(t *testing.T) {
	dsn := integrationDSN(t)
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, "mysql://"+dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate up: %v", err)
	}
	v, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("version after up: %v", err)
	}
	if dirty {
		t.Fatalf("schema DIRTY after up (version %d)", v)
	}
	// The applied version must equal the number of embedded migration files —
	// every migration in the binary applies cleanly and nothing is left pending.
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			want++
		}
	}
	if v != uint(want) {
		t.Fatalf("version = %d, want %d (all embedded migrations applied)", v, want)
	}

	// Down all the way, then re-up: proves the down-script drops everything
	// and a second deploy from scratch still works.
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate down: %v", err)
	}
	if _, _, err := m.Version(); !errors.Is(err, migrate.ErrNilVersion) {
		t.Fatalf("version after down = %v, want ErrNilVersion (no version applied)", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate re-up: %v", err)
	}
}

// TestRefreshRotationQueryPlan_D1 — phase-gate evidence: every query on the
// refresh-rotation and audit-retention paths is served by an index (no full
// table scan). The tables are seeded past the optimizer's small-table
// threshold and ANALYZEd so the plan reflects production cardinality.
func TestRefreshRotationQueryPlan_D1(t *testing.T) {
	dsn := integrationDSN(t)
	db := openIntegrationDB(t, dsn)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqlDB.Close() }()

	// Seed: 200 users × 15 refresh tokens + 15 audit rows each (3000 rows per
	// table). Rows are spread across users so user_id selectivity models
	// production cardinality — a single-user seed makes the optimizer
	// correctly prefer a full scan (100% of rows match) and proves nothing.
	users := make([]models.User, 0, 200)
	for i := 0; i < 200; i++ {
		users = append(users, models.User{
			Username: fmt.Sprintf("d1user-%03d", i),
			Email:    fmt.Sprintf("d1-%03d@example.com", i),
			Password: "hash", Role: models.RoleUser, IsActive: true,
		})
	}
	t.Cleanup(func() {
		db.Where("1 = 1").Delete(&models.RefreshToken{})
		db.Where("1 = 1").Delete(&models.AuditLog{})
		db.Where("username LIKE ?", "d1user-%").Delete(&models.User{})
	})
	db.Where("username LIKE ?", "d1user-%").Delete(&models.User{})
	if err := db.CreateInBatches(users, 100).Error; err != nil {
		t.Fatal(err)
	}
	tokens := make([]models.RefreshToken, 0, 3000)
	logs := make([]models.AuditLog, 0, 3000)
	for i, u := range users {
		for j := 0; j < 15; j++ {
			tokens = append(tokens, models.RefreshToken{
				UserID:       u.ID,
				TokenHash:    fmt.Sprintf("hash-%03d-%02d", i, j),
				ExpiresAt:    time.Now().Add(24 * time.Hour),
				LastActiveAt: time.Now(),
				CreatedAt:    time.Now(),
			})
			uid := u.ID
			logs = append(logs, models.AuditLog{
				UserID:    &uid,
				Event:     "test.event",
				IPAddress: "127.0.0.1",
				CreatedAt: time.Now().Add(-time.Duration(i*15+j) * time.Minute),
			})
		}
	}
	if err := db.CreateInBatches(tokens, 500).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.CreateInBatches(logs, 500).Error; err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"refresh_tokens", "audit_logs"} {
		if err := db.Exec("ANALYZE TABLE " + table).Error; err != nil {
			t.Fatalf("analyze %s: %v", table, err)
		}
	}
	target := users[0] // the user whose rows the plans below exercise

	// plan runs EXPLAIN <query> and fails when the top plan step is a full
	// table scan (type=ALL). Logs every plan for the phase report.
	plan := func(query string, args ...any) {
		t.Helper()
		rows, err := db.Raw("EXPLAIN "+query, args...).Rows()
		if err != nil {
			t.Fatalf("explain %q: %v", query, err)
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			row := map[string]string{}
			for i, c := range cols {
				if b, ok := vals[i].([]byte); ok {
					row[c] = string(b)
				} else if vals[i] != nil {
					row[c] = fmt.Sprint(vals[i])
				}
			}
			t.Logf("EXPLAIN %s\n  => select_type=%s table=%s type=%s key=%s rows=%s Extra=%s",
				query, row["select_type"], row["table"], row["type"], row["key"], row["rows"], row["Extra"])
			if row["type"] == "ALL" {
				t.Errorf("FULL SCAN on %s for: %s", row["table"], query)
			}
		}
	}

	// The rotation hot path (services.AuthService.Refresh):
	// 1. lookup by opaque-token hash (FindByHash),
	plan("SELECT * FROM refresh_tokens WHERE token_hash = ?", "hash-000123")
	// 2. CAS revoke of the used row (RefreshTokenRepository.Revoke),
	plan("UPDATE refresh_tokens SET revoked = ? WHERE id = ? AND revoked = ?", true, 1500, false)
	// 3. per-user session listing (FindActiveByUser),
	plan("SELECT * FROM refresh_tokens WHERE user_id = ? AND revoked = ? AND expires_at > ?", target.ID, false, time.Now())
	// 4. retention purge predicates (PurgeExpired / PurgeOlderThan),
	plan("SELECT id FROM refresh_tokens WHERE expires_at < ? LIMIT 500", time.Now().Add(-time.Hour))
	plan("SELECT id FROM audit_logs WHERE created_at < ? LIMIT 500", time.Now().Add(-time.Hour))
	// 5. audit lookups by user (G-governance queries),
	plan("SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", target.ID)
	// 6. single-use jti guard (UsedTokenRepository).
	plan("SELECT * FROM used_tokens WHERE jti = ?", "some-jti-uuid")
}

// BenchmarkRefreshRotation_D2 — measures the full rotation hot path
// (FindByHash + CAS Revoke + fresh Create) against real MySQL. D2 asked
// whether GORM overhead justifies rewriting the repository with raw SQL;
// run with:
//
//	TEST_MYSQL_DSN='...' go test -tags=integration ./internal/database/ \
//		-bench=BenchmarkRefreshRotation_D2 -benchtime=50x -run=^$
func BenchmarkRefreshRotation_D2(b *testing.B) {
	dsn := normalizedDSN(testEnv("TEST_MYSQL_DSN"))
	if testEnv("TEST_MYSQL_DSN") == "" {
		b.Skip("TEST_MYSQL_DSN not set")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		b.Fatal(err)
	}
	sqlDB, _ := db.DB()
	defer func() { _ = sqlDB.Close() }()
	ctx := context.Background()

	u := &models.User{Username: "benchuser", Email: "bench@example.com", Password: "hash", Role: models.RoleUser, IsActive: true}
	b.Cleanup(func() {
		db.Where("token_hash LIKE ?", "bench-%").Delete(&models.RefreshToken{})
		db.Where("username = ?", u.Username).Delete(&models.User{})
	})
	db.Where("token_hash LIKE ?", "bench-%").Delete(&models.RefreshToken{})
	db.Where("username = ?", u.Username).Delete(&models.User{})
	if err := db.Create(u).Error; err != nil {
		b.Fatal(err)
	}

	i := 0
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		i++
		// One rotation: insert current, find by hash, CAS-revoke.
		rt := &models.RefreshToken{
			UserID:       u.ID,
			TokenHash:    fmt.Sprintf("bench-%08d-%d", i, n),
			ExpiresAt:    time.Now().Add(time.Hour),
			LastActiveAt: time.Now(),
			CreatedAt:    time.Now(),
		}
		if err := db.WithContext(ctx).Create(rt).Error; err != nil {
			b.Fatal(err)
		}
		var found models.RefreshToken
		if err := db.WithContext(ctx).Where("token_hash = ?", rt.TokenHash).First(&found).Error; err != nil {
			b.Fatal(err)
		}
		res := db.WithContext(ctx).Model(&models.RefreshToken{}).
			Where("id = ? AND revoked = ?", found.ID, false).
			Update("revoked", true)
		if res.Error != nil || res.RowsAffected != 1 {
			b.Fatalf("CAS revoke failed: err=%v rows=%d", res.Error, res.RowsAffected)
		}
	}
}
