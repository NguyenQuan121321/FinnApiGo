package database

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/finnapigo/finnapigo/migrations"
)

// RunMigrations applies every pending migration from the embedded FS to the
// database addressed by dsn (a go-sql-driver MySQL DSN, e.g. cfg.DB.DSN()).
// It is the DEPLOY STEP (R1): production servers never auto-migrate at boot
// — run this (via cmd/migrate) as part of the rollout, before the new
// version serves traffic. ErrNoChange is success.
func RunMigrations(dsn string) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("migrations source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, "mysql://"+dsn)
	if err != nil {
		return fmt.Errorf("migrate init: %w", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// MigrationsVersion reports the applied migration version and its dirty
// state — used by `cmd/migrate version` as a deploy sanity check.
func MigrationsVersion(dsn string) (uint, bool, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return 0, false, fmt.Errorf("migrations source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, "mysql://"+dsn)
	if err != nil {
		return 0, false, fmt.Errorf("migrate init: %w", err)
	}
	defer func() { _, _ = m.Close() }()
	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return v, dirty, err
}
