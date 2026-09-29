package pownforge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// runRecord mirrors the fields of PownForge's RunRecord
// (src/pownforge/core/models/evidence.py) that Normalize/ExtractEvidence
// need. Every other RunRecord field (output, analysis, via_target,
// engagement, kill_chain_phase, artifacts, cves) is intentionally not
// modeled here -- AGENTS.md §20A.1 ("外部APIのレスポンス形式をドメイン
// モデルに直接漏らさない") means this struct exists only inside this
// package, never exported into internal/domain.
type runRecord struct {
	RunID     string      `json:"run_id"`
	Target    string      `json:"target"`
	Plugin    string      `json:"plugin"`
	CreatedAt time.Time   `json:"created_at"`
	Evidence  pfEvidence  `json:"evidence"`
	Findings  []pfFinding `json:"findings"`
}

// pfEvidence mirrors PownForge's Evidence (src/pownforge/core/models/
// evidence.py) field-for-field. Command/ReturnCode/ToolVersion are parsed
// but not used yet -- see ExtractEvidence's doc comment for what's
// actually carried into evidence.Params today (ADR 0022).
type pfEvidence struct {
	Command      []string  `json:"command"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	ReturnCode   int       `json:"returncode"`
	StdoutSHA256 string    `json:"stdout_sha256"`
	StderrSHA256 string    `json:"stderr_sha256"`
	ToolVersion  string    `json:"tool_version"`
}

// pfFinding mirrors PownForge's Finding (src/pownforge/core/models/
// finding.py) field-for-field -- field names and the severity/status/
// source enum string values are exactly PownForge's own, confirmed
// against that file, not guessed.
type pfFinding struct {
	FindingID          string   `json:"finding_id"`
	Title              string   `json:"title"`
	Detail             string   `json:"detail"`
	Source             string   `json:"source"` // "ai" | "tool" | "manual"
	Status             string   `json:"status"` // "needs-review" | "confirmed" | "false-positive"
	AttackTechniqueIDs []string `json:"attack_technique_ids"`
	CVSSScore          *float64 `json:"cvss_score"`
	CVSSVector         string   `json:"cvss_vector"`
	NativeSeverity     string   `json:"native_severity"`
}

// maxResponseBytes caps how much of a PownForge response Fetch will read.
// PownForge's `pownforge web serve` binds to 127.0.0.1 only by default and
// has no request size limit of its own (docs/handbook.md §9), so this is a
// defensive cap on this side, not a trust boundary PownForge itself
// enforces.
const maxResponseBytes = 50 << 20 // 50MiB

// httpClient is package-level so tests can point Fetch at an
// httptest.Server without a global timeout mismatch; production code
// never overrides it.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// Fetch retrieves a PownForge RunRecord's JSON from a running `pownforge
// web serve` instance's `GET /api/runs/{run_id}` (confirmed against
// src/pownforge/web/routers/runs.py's `response_model=RunRecord`) and
// returns the raw body for Normalize to parse. baseURL is the PownForge
// web root (e.g. "http://127.0.0.1:8000"), with or without a trailing
// slash. PownForge's Web API has no authentication of its own (it's
// designed to stay bound to localhost, AGENTS.md is PownForge's, not
// RiskForge's, but see PownForge docs/handbook.md §9), so this sends no
// credentials.
func Fetch(ctx context.Context, baseURL, runID string) ([]byte, error) {
	url := strings.TrimRight(baseURL, "/") + "/api/runs/" + runID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("pownforge: build request for %s: %w", url, err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pownforge: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pownforge: read response from %s: %w", url, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("pownforge: response from %s exceeds %d bytes", url, maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pownforge: %s returned %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// ExtractEvidence builds evidence.Params from a PownForge RunRecord JSON
// payload's `evidence` sub-object, for the caller to pass to
// application.Service.RecordEvidence before calling Normalize (ADR 0022 --
// bridging PownForge's own run-level Evidence into RiskForge's Evidence
// entity, AGENTS.md §20A.4). One RunRecord produces exactly one Evidence
// record, shared by every Finding it contains (PownForge's `evidence`
// covers the whole run, not one Finding), so this must be called once per
// RunRecord, before Normalize (which then stamps every RawFinding with the
// resulting evidence.ID) -- not once per Finding.
//
// Location is left empty here: unlike AssetID (which Normalize also takes
// from the caller), there is no single right answer for "where is this
// content" independent of how the caller obtained payload (a local file
// path, a PownForge URL that was fetched, or an HTTP request body with no
// location of its own) -- the caller fills Params.Location in before
// calling RecordEvidence.
//
// ContentHash uses the run's stdout_sha256 (PownForge's plugin output --
// where detection results and raw tool output live) rather than
// stderr_sha256 or a hash spanning both: this is a deliberate, documented
// choice, not an attempt to cover the run's complete output.
func ExtractEvidence(payload []byte, assetID asset.ID) (evidence.Params, error) {
	var run runRecord
	if err := json.Unmarshal(payload, &run); err != nil {
		return evidence.Params{}, fmt.Errorf("pownforge: parse run record: %w", err)
	}

	source := "pownforge"
	if run.Plugin != "" {
		source = "pownforge:" + run.Plugin
	}

	collectedAt := run.Evidence.FinishedAt
	if collectedAt.IsZero() {
		collectedAt = run.CreatedAt
	}

	return evidence.Params{
		Type:        evidence.TypeDetectionResult,
		Source:      source,
		SourceRef:   run.RunID,
		CollectedAt: collectedAt,
		AssetID:     assetID,
		ContentHash: run.Evidence.StdoutSHA256,
	}, nil
}

// Normalize parses a PownForge RunRecord JSON payload into RawFindings for
// the given RiskForge assetID (AGENTS.md §20: Scanner -> RawFinding),
// stamping each one with evidenceID (ADR 0022 -- the ID RecordEvidence
// returned for ExtractEvidence's result; pass "" if the caller chose not
// to record Evidence for this run, e.g. because ContentHash came back
// empty). Resolving PownForge's `target` (a scope-policy target name, not
// a RiskForge Asset) to assetID -- e.g. via AssetRepository.FindByHostname
// -- is fetch()'s job, deferred to a future ADR along with actually
// reaching a running PownForge instance; the caller supplies it here.
//
// A Finding with status "false-positive" is dropped entirely: a human
// already reviewed it and determined it is not a real issue, so it is not
// a RawFinding to classify at all (AGENTS.md §20A.3's review workflow, see
// docs/pownforge/core/models/finding.py's FindingStatus). Every other
// Finding becomes exactly one RawFinding; a per-item construction error
// (in practice: an empty Title, which PownForge's own schema does not
// enforce non-empty even though it is required in AGENTS.md §20A.1's
// "PownForge専用の特別経路を作らない" sense that no other adapter would
// behave differently) is skipped rather than failing the whole batch,
// mirroring rawfinding's own "分類できないことを理由に、結果を破棄しない"
// spirit -- but a malformed top-level payload is a real error.
func Normalize(payload []byte, assetID asset.ID, evidenceID evidence.ID) ([]rawfinding.RawFinding, error) {
	var run runRecord
	if err := json.Unmarshal(payload, &run); err != nil {
		return nil, fmt.Errorf("pownforge: parse run record: %w", err)
	}

	source := "pownforge"
	if run.Plugin != "" {
		source = "pownforge:" + run.Plugin
	}

	out := make([]rawfinding.RawFinding, 0, len(run.Findings))
	for _, f := range run.Findings {
		if f.Status == "false-positive" {
			continue
		}

		sourceRef := f.FindingID
		if run.RunID != "" {
			sourceRef = run.RunID + ":" + f.FindingID
		}

		rf, err := rawfinding.New(rawfinding.Params{
			Source:             source,
			SourceRef:          sourceRef,
			AssetID:            assetID,
			EvidenceID:         evidenceID,
			Title:              f.Title,
			Detail:             f.Detail,
			Confidence:         confidenceFromFinding(f),
			CVSSScore:          f.CVSSScore,
			CVSSVector:         f.CVSSVector,
			NativeSeverity:     f.NativeSeverity,
			AttackTechniqueIDs: f.AttackTechniqueIDs,
			CollectedAt:        run.CreatedAt,
		})
		if err != nil {
			continue
		}
		out = append(out, *rf)
	}
	return out, nil
}

// confidenceFromFinding maps PownForge's (source, status) pair onto
// finding.Confidence, per AGENTS.md §20A.3 ("手動exploitまたは攻撃シミュ
// レーションで成立を確認した場合のみconfirmedを検討できる"):
//
//   - status="confirmed" (a human ran `pownforge result review` and
//     confirmed it) -> ConfidenceConfirmed, the only case that qualifies.
//   - status="needs-review", source="tool" (a plugin's own tool-native
//     detection, e.g. a nuclei template match -- structurally solid but
//     not yet human-reviewed) -> ConfidenceMedium.
//   - status="needs-review", source="ai" (an unverified LLM guess from
//     `pownforge analyze`, per finding.py's own docstring) -> ConfidenceLow.
//   - status="needs-review", source="manual" or anything else -> ConfidenceMedium
//     (a human entered it deliberately, even if not yet confirmed).
//   - any other status (including unrecognized values) -> ConfidenceUnknown.
func confidenceFromFinding(f pfFinding) finding.Confidence {
	switch f.Status {
	case "confirmed":
		return finding.ConfidenceConfirmed
	case "needs-review":
		if strings.EqualFold(f.Source, "ai") {
			return finding.ConfidenceLow
		}
		return finding.ConfidenceMedium
	default:
		return finding.ConfidenceUnknown
	}
}
