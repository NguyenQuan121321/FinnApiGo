//go:build integration

package services

import (
	"context"
	"database/sql"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/store"
)

// A migrated, uniquely named disposable schema. Never connect to an existing
// application schema. Missing real-service inputs FAIL rather than skip CI.
func TestF02RealUserMutations(t *testing.T) {
	if os.Getenv("F02_MYSQL_ALLOW_CREATE_DROP") != "1" || os.Getenv("F02_MYSQL_ADMIN_DSN") == "" || os.Getenv("TEST_REDIS_URL") == "" {
		t.Fatal("BLOCKED: explicit disposable F02 MySQL and Redis inputs required")
	}
	cfg, err := mysql.ParseDSN(os.Getenv("F02_MYSQL_ADMIN_DSN"))
	mutationMust(t, err)
	host, _, err := net.SplitHostPort(cfg.Addr)
	mutationMust(t, err)
	if cfg.Net != "tcp" || (host != "127.0.0.1" && host != "::1") || cfg.DBName != "" {
		t.Fatal("disposable loopback MySQL admin without existing schema required")
	}
	cfg.ParseTime, cfg.Loc = true, time.UTC
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	mutationMust(t, err)
	t.Cleanup(func() { mutationMust(t, admin.Close()) })
	schema := "finnapigo_f02_repair_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE DATABASE `" + schema + "` CHARACTER SET utf8mb4")
	mutationMust(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP DATABASE `" + schema + "`"); mutationMust(t, err) })
	cfg.DBName = schema
	mutationMust(t, database.RunMigrations(cfg.FormatDSN()))
	version, dirty, err := database.MigrationsVersion(cfg.FormatDSN())
	mutationMust(t, err)
	if version != 5 || dirty {
		t.Fatalf("migration version=%d dirty=%v", version, dirty)
	}
	db, err := gorm.Open(mysqldriver.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Discard})
	mutationMust(t, err)
	conn, err := db.DB()
	mutationMust(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	opts, err := redis.ParseURL(os.Getenv("TEST_REDIS_URL"))
	mutationMust(t, err)
	rh, _, err := net.SplitHostPort(opts.Addr)
	mutationMust(t, err)
	if rh != "127.0.0.1" && rh != "::1" {
		t.Fatal("loopback Redis required")
	}
	opts.DB = 14 // other integration suites use default and F02 state uses 15.
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	mutationMust(t, client.Ping(context.Background()).Err())
	runStaleUserMutations(t, db, store.NewRedisStore(client))
	runMutationOwnership(t, db)
	runMutationAdapterFailure(t, db)
	if t.Failed() {
		t.Fatal("real mutation acceptance failed")
	}
	t.Logf("real migrated MySQL schema=%s and Redis DB14: service/repository interleavings, new login and old-session revocation passed", schema)
}
