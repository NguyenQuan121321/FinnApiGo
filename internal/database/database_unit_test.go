package database

import (
	"strings"
	"testing"

	"github.com/finnapigo/finnapigo/internal/config"
)

func TestConnect_EmptyHost(t *testing.T) {
	cfg := config.DBConfig{Host: ""}
	_, err := Connect(cfg)
	if err == nil || !strings.Contains(err.Error(), "DB_HOST is empty") {
		t.Fatalf("expected DB_HOST is empty error, got: %v", err)
	}
}

func TestRunMigrations_InvalidDSN(t *testing.T) {
	err := RunMigrations("invalid:dsn:format@@")
	if err == nil {
		t.Fatal("expected error on invalid DSN for RunMigrations")
	}
}

func TestMigrationsVersion_InvalidDSN(t *testing.T) {
	_, _, err := MigrationsVersion("invalid:dsn:format@@")
	if err == nil {
		t.Fatal("expected error on invalid DSN for MigrationsVersion")
	}
}

func TestConnect_PingFail(t *testing.T) {
	cfg := config.DBConfig{
		Host:         "127.0.0.1",
		Port:         "1",
		User:         "root",
		Password:     "password",
		Name:         "testdb",
		MaxIdleConns: 5,
		MaxOpenConns: 10,
	}
	_, err := Connect(cfg)
	if err == nil || !strings.Contains(err.Error(), "open mysql") {
		t.Fatalf("expected open mysql error, got: %v", err)
	}
}
