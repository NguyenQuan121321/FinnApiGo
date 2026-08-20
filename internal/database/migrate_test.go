package database

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/finnapigo/finnapigo/migrations"
)

// TestMigrationsSourceParses_R1 — R1: the embedded migration set must parse
// with the exact golang-migrate naming convention ({version}_{name}.up/.down)
// and contain the baseline pair.
func TestMigrationsSourceParses_R1(t *testing.T) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var ups, downs int
	for _, e := range entries {
		switch e.Name() {
		case "0001_init.up.sql":
			ups++
		case "0001_init.down.sql":
			downs++
		}
	}
	if ups != 1 || downs != 1 {
		t.Fatalf("baseline migration pair missing: ups=%d downs=%d", ups, downs)
	}
	// Every table the models define must appear in the up migration.
	upSQL, err := fs.ReadFile(migrations.FS, "0001_init.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"users", "refresh_tokens", "audit_logs", "used_tokens",
		"totp_devices", "recovery_codes", "oauth_identities",
	} {
		if !strings.Contains(string(upSQL), "CREATE TABLE IF NOT EXISTS `"+table+"`") {
			t.Errorf("migration is missing table %s", table)
		}
	}
	// ...and the down migration must drop each of them.
	downSQL, err := fs.ReadFile(migrations.FS, "0001_init.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"users", "refresh_tokens", "audit_logs", "used_tokens",
		"totp_devices", "recovery_codes", "oauth_identities",
	} {
		if !strings.Contains(string(downSQL), "DROP TABLE IF EXISTS `"+table+"`") {
			t.Errorf("down migration is missing table %s", table)
		}
	}
}
