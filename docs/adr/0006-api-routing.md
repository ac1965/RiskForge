# 0006. API routing

## Status

Accepted

## Context

The API layer (AGENTS.md §28) needs an HTTP routing approach. Third-party
routers (chi, gorilla/mux, gin, etc.) add a dependency and a
router-specific handler signature across the whole API surface for a
problem the standard library now covers.

## Decision

Use the standard library's `net/http` with `http.ServeMux` for API routing.
Handlers are implemented as plain `http.Handler`; middleware (auth,
request logging, request ID) is implemented as `http.Handler` wrappers,
not as router-specific middleware.

No routing library (chi, gorilla/mux, gin, echo, ...) is introduced without
a new ADR superseding this one (AGENTS.md §25A.8).

## Consequences

- Middleware and handlers stay portable if the routing library decision is
  revisited later — an ADR-gated change, not a casual dependency bump
  (AGENTS.md §48).
- Route pattern matching is limited to what `http.ServeMux` supports
  (method + path pattern matching, available since Go 1.22).
