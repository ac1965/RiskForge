package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// This file is the HTTP counterpart of `riskforge scanner import-pownforge`
// (ADR 0015-0022): POST /api/v1/scanner/pownforge-import. Like
// internal/cli, this package must not import internal/infrastructure
// directly (AGENTS.md §25 Layering) -- cmd/riskforge/main.go injects
// internal/infrastructure/scanner/pownforge.Normalize/Fetch/ExtractEvidence
// as plain function values into NewMux, the same pattern
// internal/cli/root.go already uses for
// PownForgeNormalizer/PownForgeFetcher/PownForgeEvidenceExtractor.

// PownForgeNormalizer, PownForgeFetcher, and PownForgeEvidenceExtractor
// mirror internal/cli's own identically-named types (ADR 0018/0020/0022).
// They are redeclared here rather than imported from internal/cli, which
// this package (a sibling UI-layer driving adapter, not a dependency of
// internal/cli) must not depend on.
type PownForgeNormalizer func(payload []byte, assetID asset.ID, evidenceID evidence.ID) ([]rawfinding.RawFinding, error)
type PownForgeFetcher func(ctx context.Context, baseURL, runID string) ([]byte, error)
type PownForgeEvidenceExtractor func(payload []byte, assetID asset.ID) (evidence.Params, error)

// pownforgeImportBody is POST /api/v1/scanner/pownforge-import's request
// shape. Exactly one of RunRecord (the PownForge RunRecord JSON, embedded
// verbatim so Normalize sees PownForge's own bytes unmodified) or
// PownForgeURL+RunID (fetched server-side) must be given, mirroring the
// CLI's <file> vs --pownforge-url/--run-id split. Exactly one of AssetID
// or Target, mirroring --asset/--target.
//
// Location records where RunRecord's bytes came from, for the Evidence
// entry (ADR 0022) -- required when RunRecord is embedded directly
// (nothing else identifies where the caller got it from); derived
// automatically from PownForgeURL+RunID when fetched server-side, the same
// way the CLI derives it, so it is ignored in that mode. SkipEvidence
// mirrors the CLI's --skip-evidence.
type pownforgeImportBody struct {
	RunRecord    json.RawMessage
	PownForgeURL string
	RunID        string
	AssetID      string
	Target       string
	Location     string
	SkipEvidence bool
}

// pownforgeImportResult mirrors one row of `scanner import-pownforge`'s
// tabular CLI output.
type pownforgeImportResult struct {
	Title     string
	Outcome   string
	FindingID string
}

func handleImportPownForge(svc *application.Service, normalizePownForge PownForgeNormalizer, fetchPownForge PownForgeFetcher, extractPownForgeEvidence PownForgeEvidenceExtractor) http.HandlerFunc {
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
		if haveEmbedded && !body.SkipEvidence && body.Location == "" {
			writeError(w, http.StatusBadRequest, errors.New("Location is required with an embedded RunRecord unless SkipEvidence is true (ADR 0022): nothing else identifies where it came from"))
			return
		}

		payload := []byte(body.RunRecord)
		location := body.Location
		if haveFetch {
			fetched, err := fetchPownForge(r.Context(), body.PownForgeURL, body.RunID)
			if err != nil {
				// 502: the failure is PownForge's/the network's, not this
				// request's own shape.
				writeError(w, http.StatusBadGateway, fmt.Errorf("fetch run %s from %s: %w", body.RunID, body.PownForgeURL, err))
				return
			}
			payload = fetched
			location = strings.TrimRight(body.PownForgeURL, "/") + "/api/runs/" + body.RunID
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

		var evidenceID evidence.ID
		if !body.SkipEvidence {
			evParams, err := extractPownForgeEvidence(payload, assetID)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("extract evidence: %w", err))
				return
			}
			if evParams.ContentHash != "" {
				evParams.Location = location
				ev, err := svc.RecordEvidence(r.Context(), evParams)
				if err != nil {
					writeError(w, http.StatusBadRequest, fmt.Errorf("record evidence: %w", err))
					return
				}
				evidenceID = ev.ID
			}
			// Same as the CLI (ADR 0022): an empty ContentHash means the
			// payload's `evidence` sub-object was missing/empty, so there
			// is nothing valid to record -- proceed without Evidence
			// rather than fail the whole import over it.
		}

		rawFindings, err := normalizePownForge(payload, assetID, evidenceID)
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
