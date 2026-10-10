//go:build integration

package tenantboundary_test

import (
	"database/sql"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// F01 uses its own newly created schema, separate from all other test suites.
// Explicit opt-in and loopback-only access prevent production configuration
// from being accidentally reused. Missing environment is a failure, not skip.
func TestF01MySQL(t *testing.T) {
	if os.Getenv("F01_MYSQL_ALLOW_CREATE_DROP") != "1" || os.Getenv("F01_MYSQL_ADMIN_DSN") == "" {
		t.Fatal("BLOCKED: provide F01_MYSQL_ADMIN_DSN for isolated loopback MySQL and F01_MYSQL_ALLOW_CREATE_DROP=1")
	}
	cfg, err := mysql.ParseDSN(os.Getenv("F01_MYSQL_ADMIN_DSN"))
	if err != nil {
		t.Fatal("invalid F01 MySQL DSN")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil || cfg.Net != "tcp" || (host != "127.0.0.1" && host != "::1") || cfg.DBName != "" {
		t.Fatal("F01 requires loopback TCP MySQL admin DSN with no existing database selected")
	}
	cfg.ParseTime = true
	adminDB, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("cannot open isolated MySQL")
	}
	t.Cleanup(func() {
		if err := adminDB.Close(); err != nil {
			t.Error(err)
		}
	})
	schema := "finnapigo_f01_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminDB.Exec("CREATE DATABASE `" + schema + "` CHARACTER SET utf8mb4"); err != nil {
		t.Fatal("cannot create isolated F01 schema")
	}
	t.Cleanup(func() {
		if _, err := adminDB.Exec("DROP DATABASE `" + schema + "`"); err != nil {
			t.Error("isolated schema cleanup failed")
		}
	})
	cfg.DBName = schema
	if err := database.RunMigrations(cfg.FormatDSN()); err != nil {
		t.Fatal(err)
	}
	version, dirty, err := database.MigrationsVersion(cfg.FormatDSN())
	if err != nil || dirty || version != 4 {
		t.Fatalf("migration state: version=%d dirty=%v err=%v", version, dirty, err)
	}
	db, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal("cannot open migrated F01 schema")
	}
	conn, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Logf("real MySQL; isolated schema %s; migrations version=%d; clientFoundRows=%v", schema, version, cfg.ClientFoundRows)
	runF01Matrix(t, db)
	// Predicates use existing tenant and owner indexes; no schema change.
	for _, index := range []struct{ table, name string }{
		{"users", "idx_users_tenant_id"},
		{"sessions", "idx_sessions_tenant_id"},
		{"refresh_tokens", "idx_refresh_tokens_user_id"},
		{"audit_logs", "idx_audit_logs_tenant_created"},
	} {
		var count int64
		if err := db.Raw("SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND INDEX_NAME = ?", schema, index.table, index.name).Scan(&count).Error; err != nil || count == 0 {
			t.Fatalf("required index %s.%s missing: count=%d err=%v", index.table, index.name, count, err)
		}
		t.Logf("required index present: %s.%s", index.table, index.name)
	}
	type explainRow struct {
		Table        string
		Type         string
		PossibleKeys sql.NullString `gorm:"column:possible_keys"`
		Key          sql.NullString
		Rows         uint64
		Extra        sql.NullString
	}
	for _, query := range []string{
		"EXPLAIN SELECT * FROM users WHERE id = 1 AND tenant_id = 'default'",
		"EXPLAIN SELECT * FROM sessions WHERE tenant_id = 'default'",
		"EXPLAIN SELECT * FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE tenant_id = 'default')",
		"EXPLAIN SELECT * FROM audit_logs WHERE tenant_id = 'default' ORDER BY created_at DESC LIMIT 20",
	} {
		var plan []explainRow
		if err := db.Raw(query).Scan(&plan).Error; err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %+v", query, plan)
	}
}
