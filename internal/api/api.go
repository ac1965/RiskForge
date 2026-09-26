package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ac1965/riskforge/internal/application"
)

// NewMux builds the read-only HTTP API decided by ADR 0011 (P0-2): five
// GET endpoints, each a thin wrapper around an existing
// application.Service "List*" method. It is the package's only exported
// entry point; individual handlers and the JSON encode/decode helpers
// stay unexported.
func NewMux(svc *application.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/assets", handleList(svc.ListAssets))
	mux.HandleFunc("GET /api/v1/findings", handleList(svc.ListFindings))
	mux.HandleFunc("GET /api/v1/priorities", handleList(svc.ListPriorities))
	mux.HandleFunc("GET /api/v1/remediation-plans", handleList(svc.ListRemediationPlans))
	mux.HandleFunc("GET /api/v1/exceptions", handleList(svc.ListExceptions))
	return mux
}

// handleList adapts a Service "List*" method — every one of the five
// endpoints has the same (ctx) ([]T, error) shape — into a handler that
// writes the list as a JSON array (never `null`, even when empty) on
// success, or {"error": "..."} with 500 on failure (ADR 0011; this PR's
// scope has no per-resource 404 case, since there is no ID-lookup
// endpoint yet).
func handleList[T any](list func(ctx context.Context) ([]T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := list(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if items == nil {
			items = []T{}
		}
		writeJSON(w, http.StatusOK, items)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError reports err's own message, matching internal/cli/output.go's
// existing practice of surfacing Application's error text as-is (ADR
// 0011): Application already keeps that text free of internals such as
// raw SQL errors or credentials (AGENTS.md §31).
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
