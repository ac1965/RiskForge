package cli

import "github.com/ac1965/riskforge/internal/application"

// ServiceFactory lazily constructs a ready-to-use application.Service and
// returns a function to release its resources (e.g. closing a database
// connection pool). Commands call it inside RunE, not at construction
// time, so `riskforge --help` never needs a database.
//
// This package depends only on internal/application (and internal/domain
// value types for building request parameters) — never on
// internal/infrastructure directly (AGENTS.md §25 Layering).
// cmd/riskforge provides the concrete factory that wires in PostgreSQL.
type ServiceFactory func() (*application.Service, func() error, error)
