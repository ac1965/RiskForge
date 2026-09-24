// Package postgres implements repository interfaces defined by the domain
// and application layers against PostgreSQL (AGENTS.md §25A.1, §29).
//
// Schema migrations live under /migrations and are managed with
// golang-migrate; this package must not embed schema definitions inline.
package postgres
