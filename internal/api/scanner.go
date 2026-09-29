package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// This file is the HTTP counterpart of `riskforge scanner import-pownforge`
// (ADR 0015-0020): POST /api/v1/scanner/pownforge-import. Like
// internal/cli, this package must not import internal/infrastructure
// directly (AGENTS.md §25 Layering) -- cmd/riskforge/main.go injects
// internal/infrastructure/scanner/pownforge.Normalize/Fetch as plain
// function values into NewMux, the same pattern internal/cli/root.go
// already uses for PownForgeNormalizer/PownForgeFetcher.

// PownForgeNormalizer and PownForgeFetcher mirror internal/cli's own
// identically-named types (ADR 0018/0020). They are redeclared here
// rather than imported from internal/cli, which this package (a sibling
// UI-layer driving adapter, not a dependency of internal/cli) must not
// depend on.
type PownForgeNormalizer func(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error)
type PownForgeFetcher func(ctx context.Context, baseURL, runID string) ([]byte, error)

// pownforgeImportBody is POST /api/v1/scanner/pownforge-import's request
// shape. Exactly one of RunRecord (the PownForge RunRecord JSON, embedded
// verbatim so Normalize sees PownForge's own bytes unmodified) or
// PownForgeURL+RunID (fetched server-side) must be given, mirroring the
// CLI's <file> vs --pownforge-url/--run-id split. Exactly one of AssetID
// or Target, mirroring --asset/--target.
type pownforgeImportBody struct {
	RunRecord    json.RawMessage
	PownForgeURL string
	RunID        string
	AssetID      string
	Target       string
}

// pownforgeImportResult mirrors one row of `scanner import-pownforge`'s
// tabular CLI output.
type pownforgeImportResult struct {
	Title     string
	Outcome   string
	FindingID string
}

func handleImportPownForge(svc *application.Service, normalizePownForge PownForgeNormalizer, fetchPownForge PownForgeFetcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body pownforgeImportBody
		if err := decodeJSONBody(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode request body: %w", err))
			return
		}

		haveEmbedded := len(body.RunRecord) > 0
		haveFetch := body.PownForgeURL != "" || body.RunID != ""
		switch {
		case haveEmbedded && haveFetch:
			writeError(w, http.StatusBadRequest, errors.New("give either RunRecord or PownForgeURL/RunID, not both"))
			return
		case !haveEmbedded && !haveFetch:
			writeError(w, http.StatusBadRequest, errors.New("give either RunRecord or both PownForgeURL and RunID"))
			return
		case haveFetch && (body.PownForgeURL == "" || body.RunID == ""):
			writeError(w, http.StatusBadRequest, errors.New("PownForgeURL and RunID must be given together"))
			return
		}
		if (body.AssetID == "") == (body.Target == "") {
			writeError(w, http.StatusBadRequest, errors.New("give exactly one of AssetID or Target"))
			return
		}

		payload := []byte(body.RunRecord)
		if haveFetch {
			fetched, err := fetchPownForge(r.Context(), body.PownForgeURL, body.RunID)
			if err != nil {
				// 502: the failure is PownForge's/the network's, not this
				// request's own shape.
				writeError(w, http.StatusBadGateway, fmt.Errorf("fetch run %s from %s: %w", body.RunID, body.PownForgeURL, err))
				return
			}
			payload = fetched
		}

		assetID := asset.ID(body.AssetID)
		if body.Target != "" {
			a, err := resolveTargetAsset(r.Context(), svc, body.Target)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("resolve Target: %w", err))
				return
			}
			assetID = a.ID
		}

		rawFindings, err := normalizePownForge(payload, assetID)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("normalize: %w", err))
			return
		}

		results := make([]pownforgeImportResult, 0, len(rawFindings))
		for _, rf := range rawFindings {
			f, outcome, err := svc.MatchRawFinding(r.Context(), rf)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("match %q: %w", rf.Title, err))
				return
			}
			result := pownforgeImportResult{Title: rf.Title, Outcome: string(outcome)}
			if f != nil {
				result.FindingID = string(f.ID)
			}
			results = append(results, result)
		}
		writeJSON(w, http.StatusOK, results)
	}
}

// resolveTargetAsset mirrors internal/cli/scanner.go's --target handling:
// discover_assets() by hostname, with `asset discover`'s own defaults
// when only a hostname is known (ADR 0020 found the hard way that
// asset.New rejects a bare Hostname -- Type is required).
func resolveTargetAsset(ctx context.Context, svc *application.Service, hostname string) (*asset.Asset, error) {
	now := time.Now()
	return svc.DiscoverAssets(ctx, asset.Params{
		Hostname:       hostname,
		Type:           asset.TypeUnknown,
		Environment:    asset.EnvironmentUnknown,
		Criticality:    asset.CriticalityUnknown,
		Exposure:       asset.Exposure{Level: asset.LevelUnknown},
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: asset.LifecycleActive,
	}, now)
}
