package pownforge

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// runRecord mirrors the fields of PownForge's RunRecord
// (src/pownforge/core/models/evidence.py) that Normalize needs. Every
// other RunRecord field (evidence, output, analysis, via_target,
// engagement, kill_chain_phase, artifacts, cves) is intentionally not
// modeled here -- AGENTS.md §20A.1 ("外部APIのレスポンス形式をドメイン
// モデルに直接漏らさない") means this struct exists only inside this
// package, never exported into internal/domain.
type runRecord struct {
	RunID     string      `json:"run_id"`
	Target    string      `json:"target"`
	Plugin    string      `json:"plugin"`
	CreatedAt time.Time   `json:"created_at"`
	Findings  []pfFinding `json:"findings"`
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

// Normalize parses a PownForge RunRecord JSON payload into RawFindings for
// the given RiskForge assetID (AGENTS.md §20: Scanner -> RawFinding).
// Resolving PownForge's `target` (a scope-policy target name, not a
// RiskForge Asset) to assetID -- e.g. via AssetRepository.FindByHostname --
// is fetch()'s job, deferred to a future ADR along with actually reaching
// a running PownForge instance; the caller supplies it here.
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
func Normalize(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error) {
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
