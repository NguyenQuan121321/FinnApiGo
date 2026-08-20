// Package migrations embeds the SQL migration files (R1). Keeping them in a
// dedicated package lets both the deploy binary and tests consume the exact
// bytes that ship with the build.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
