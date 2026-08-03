// Package database sets up the GORM/MySQL connection used across the app.
package database

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/config"
)

// Connect opens the MySQL connection, configures the connection pool, and
// returns a ready-to-use *gorm.DB. It does NOT auto-migrate — migrations
// are an explicit, separate step (see cmd/server/main.go).
func Connect(cfg config.DBConfig) (*gorm.DB, error) {
	logLevel := logger.Warn
	if cfg.Host == "" {
		return nil, fmt.Errorf("database: DB_HOST is empty")
	}

	db, err := gorm.Open(mysql.Open(cfg.DSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("database: open mysql: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("database: acquire underlying *sql.DB: %w", err)
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("database: ping: %w", err)
	}
	return db, nil
}
