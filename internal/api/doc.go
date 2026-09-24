// Package api implements the HTTP API using net/http's ServeMux
// (AGENTS.md §25A.8 — chi or other routers require an ADR to introduce).
//
// Handlers stay as plain http.Handler; middleware (auth, logging, request
// ID) wraps http.Handler rather than adopting a router-specific signature.
// Resources are separated per §28 (e.g. Finding and Vulnerability are never
// the same resource).
package api
