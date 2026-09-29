package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/authn"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// NewMux builds the HTTP API: the read-only GET endpoints decided by
// ADR 0011 (P0-2, the original 5) plus vulnerabilities/verifications
// (added when the Dashboard's KPI work actually needed them — ADR 0011
// itself flagged these as a deliberate, not-yet-necessary gap), all
// gated by RequireScope's "read" scope (ADR 0012), the Exception write
// endpoints decided by ADR 0014 (P0-3's first slice), gated by
// "exception:request"/"exception:approve", and
// POST /api/v1/scanner/pownforge-import (ADR 0021), gated by
// "scanner:import". It is the package's only exported entry point for
// building the handler; individual handlers and the JSON encode/decode
// helpers stay unexported.
//
// normalizePownForge/fetchPownForge are declared with their raw,
// unnamed function type here (not the PownForgeNormalizer/PownForgeFetcher
// aliases scanner.go uses internally) on purpose: internal/cli's
// HandlerFactory (serve.go) must stay assignable from this exact
// signature without internal/cli importing this package's named types
// (ADR 0011's existing "internal/cli never imports internal/api"
// boundary) — two distinctly-named function types with identical
// underlying signatures are not interchangeable at a call boundary,
// only structurally identical unnamed ones are.
func NewMux(
	svc *application.Service,
	normalizePownForge func(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error),
	fetchPownForge func(ctx context.Context, baseURL, runID string) ([]byte, error),
) http.Handler {
	mux := http.NewServeMux()
	requireRead := RequireScope(svc, authn.ScopeRead)
	requireExceptionRequest := RequireScope(svc, authn.ScopeExceptionRequest)
	requireExceptionApprove := RequireScope(svc, authn.ScopeExceptionApprove)
	requireScannerImport := RequireScope(svc, authn.ScopeScannerImport)

	mux.Handle("GET /api/v1/assets", requireRead(handleList(svc.ListAssets)))
	mux.Handle("GET /api/v1/findings", requireRead(handleList(svc.ListFindings)))
	mux.Handle("GET /api/v1/priorities", requireRead(handleList(svc.ListPriorities)))
	mux.Handle("GET /api/v1/remediation-plans", requireRead(handleList(svc.ListRemediationPlans)))
	mux.Handle("GET /api/v1/exceptions", requireRead(handleList(svc.ListExceptions)))
	mux.Handle("GET /api/v1/vulnerabilities", requireRead(handleList(svc.ListVulnerabilities)))
	mux.Handle("GET /api/v1/verifications", requireRead(handleList(svc.ListVerifications)))

	mux.Handle("POST /api/v1/exceptions", requireExceptionRequest(handleRequestException(svc)))
	mux.Handle("POST /api/v1/exceptions/{id}/approve", requireExceptionApprove(handleApproveException(svc)))
	mux.Handle("POST /api/v1/exceptions/{id}/reject", requireExceptionApprove(handleRejectException(svc)))
	mux.Handle("POST /api/v1/exceptions/{id}/expire", requireExceptionApprove(handleExpireException(svc)))
	mux.Handle("POST /api/v1/exceptions/{id}/revoke", requireExceptionApprove(handleRevokeException(svc)))

	mux.Handle("POST /api/v1/scanner/pownforge-import", requireScannerImport(handleImportPownForge(svc, normalizePownForge, fetchPownForge)))

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
