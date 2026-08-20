// Command finnapigo-migrate is the schema deploy step (R1): it applies the
// embedded golang-migrate migrations to the database configured via the
// standard DB_* environment variables (.env supported). Production servers
// boot with AutoMigrate OFF; run this binary during the rollout.
//
// Usage:
//
//	go run ./cmd/migrate up          # apply all pending
//	go run ./cmd/migrate down 1      # roll back N versions
//	go run ./cmd/migrate force 1     # force-set version (recovery only)
//	go run ./cmd/migrate version     # show applied version + dirty flag
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

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
	default:
		fatal("usage", fmt.Errorf("unknown subcommand %q (want up|down|force|version)", cmd))
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
