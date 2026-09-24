// Package migrations embeds the SQL files in this directory so
// internal/infrastructure/postgres can apply them without requiring the
// golang-migrate CLI to be installed separately.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
