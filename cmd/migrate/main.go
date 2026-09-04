// Command finnapigo-migrate is the schema deploy step (R1): it applies the
// embedded golang-migrate migrations to the database configured via the
// standard DB_* environment variables (.env supported). Production servers
// boot with AutoMigrate OFF; run this binary during the rollout.
//
// Usage:
//
//	go run ./cmd/migrate up          # apply all pending
//	go run ./cmd/migrate down 1      # roll back N versions (or 'down all')
//	go run ./cmd/migrate force 1     # force-set version (recovery only)
//	go run ./cmd/migrate version     # show applied version + dirty flag
//	go run ./cmd/migrate check up    # verify non-dirty schema & required tables
//	go run ./cmd/migrate check down  # verify clean rollback (0 app tables)
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/joho/godotenv"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/migrations"
)

func main() {
	_ = godotenv.Load()
	dsn := config.DBConfig{
		Host:     envOr("DB_HOST", "127.0.0.1"),
		Port:     envOr("DB_PORT", "3306"),
		User:     envOr("DB_USER", "finnapigo"),
		Password: envOr("DB_PASSWORD", ""),
		Name:     envOr("DB_NAME", "finnapigo"),
		TLS:      envOr("DB_TLS", ""),
	}.DSN()

	// golang-migrate requires multiStatements=true to execute SQL files with multiple statements
	if !strings.Contains(dsn, "multiStatements") {
		sep := "&"
		if !strings.Contains(dsn, "?") {
			sep = "?"
		}
		dsn += sep + "multiStatements=true"
	}

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		fatal("migrations source", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, "mysql://"+dsn)
	if err != nil {
		fatal("migrate init", err)
	}
	defer func() { _, _ = m.Close() }()

	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "up":
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			fatal("migrate up", err)
		}
		v, dirty, _ := m.Version()
		slog.Info("migrate: up complete", "version", v, "dirty", dirty)
	case "down":
		n := 1
		if len(os.Args) > 2 {
			if os.Args[2] == "all" {
				if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
					fatal("migrate down all", err)
				}
				slog.Info("migrate: down all complete")
				return
			}
			if parsed, err := strconv.Atoi(os.Args[2]); err == nil {
				n = parsed
			}
		}
		if err := m.Steps(-n); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			fatal("migrate down", err)
		}
		slog.Info("migrate: down complete", "steps", n)
	case "force":
		if len(os.Args) < 3 {
			fatal("force", errors.New("usage: force <version>"))
		}
		v, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fatal("force", err)
		}
		if err := m.Force(v); err != nil {
			fatal("force", err)
		}
		slog.Info("migrate: version forced", "version", v)
	case "version":
		v, dirty, err := m.Version()
		if errors.Is(err, migrate.ErrNilVersion) {
			fmt.Println("version: none (fresh database)")
			return
		}
		if err != nil {
			fatal("version", err)
		}
		fmt.Printf("version: %d dirty: %v\n", v, dirty)
	case "check":
		mode := "up"
		if len(os.Args) > 2 {
			mode = os.Args[2]
		}
		checkSchema(dsn, mode, m)
	default:
		fatal("usage", fmt.Errorf("unknown subcommand %q (want up|down|force|version|check)", cmd))
	}
}

func checkSchema(dsn, mode string, m *migrate.Migrate) {
	v, dirty, err := m.Version()
	switch mode {
	case "up":
		if err != nil {
			fatal("check up: version", err)
		}
		if dirty {
			fatal("check up: schema dirty", fmt.Errorf("schema version %d is dirty", v))
		}
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			fatal("check up: db open", err)
		}
		defer func() { _ = db.Close() }()

		dbName := envOr("DB_NAME", "finnapigo")
		expectedTables := []string{
			"users", "refresh_tokens", "audit_logs", "used_tokens",
			"totp_devices", "recovery_codes", "oauth_identities",
			"passkey_credentials", "sessions", "tenants",
			"permissions", "roles", "role_permissions", "user_roles",
			"trusted_devices", "webhook_endpoints", "webhook_deliveries",
			"schema_migrations",
		}
		for _, tbl := range expectedTables {
			var count int
			row := db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?", dbName, tbl)
			if err := row.Scan(&count); err != nil {
				fatal("check up: query table "+tbl, err)
			}
			if count != 1 {
				fatal("check up: missing table", fmt.Errorf("expected table %q not found in schema %q", tbl, dbName))
			}
		}
		slog.Info("migrate check: up verification succeeded", "version", v, "dirty", dirty, "tables_verified", len(expectedTables))
	case "down":
		if !errors.Is(err, migrate.ErrNilVersion) {
			fatal("check down: version", fmt.Errorf("expected ErrNilVersion, got version=%d dirty=%v err=%w", v, dirty, err))
		}
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			fatal("check down: db open", err)
		}
		defer func() { _ = db.Close() }()

		dbName := envOr("DB_NAME", "finnapigo")
		rows, err := db.Query("SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_name != 'schema_migrations'", dbName)
		if err != nil {
			fatal("check down: query remaining tables", err)
		}
		defer func() { _ = rows.Close() }()

		var remaining []string
		for rows.Next() {
			var t string
			if err := rows.Scan(&t); err == nil {
				remaining = append(remaining, t)
			}
		}
		if err := rows.Err(); err != nil {
			fatal("check down: scan tables", err)
		}
		if len(remaining) > 0 {
			fatal("check down: remaining application tables", fmt.Errorf("expected 0 remaining tables, found: %v", remaining))
		}
		slog.Info("migrate check: down verification succeeded (clean rollback, 0 application tables remaining)")
	default:
		fatal("check", fmt.Errorf("unknown mode %q (want up|down)", mode))
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(what string, err error) {
	slog.Error("migrate fatal", "step", what, "err", err)
	os.Exit(1)
}
