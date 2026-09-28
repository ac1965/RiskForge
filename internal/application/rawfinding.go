package application

import (
	"context"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// MatchOutcome describes what MatchRawFinding did with a RawFinding -- the
// Matcher stage of the Scanner pipeline (AGENTS.md §20, §20A.2).
type MatchOutcome string

const (
	// MatchOutcomeCorrelated means rf's extracted CVE matched an existing
	// Vulnerability, and a Finding was created or confirmed for it.
	MatchOutcomeCorrelated MatchOutcome = "correlated"
	// MatchOutcomeUnmatched means rf named a CVE
	// (ClassificationKnownVulnerability) but no Vulnerability record for
	// it exists yet in this RiskForge instance. Creating one from a bare
	// RawFinding is out of scope here (ADR 0016 "対象外") -- rf is held,
	// not discarded (AGENTS.md §20A.2: "分類できないことを理由に、結果を
	// 破棄しない" applies just as much to "not yet registered" as to
	// "unclassifiable").
	MatchOutcomeUnmatched MatchOutcome = "unmatched"
	// MatchOutcomeHeld means rawfinding.Classify did not return
	// ClassificationKnownVulnerability (either ClassificationUnknownVulnerability
	// or ClassificationUnclassified) -- registering a new CVE-less
	// Vulnerability, and persisting a held RawFinding for later review,
	// are both out of scope here (ADR 0016 "対象外").
	MatchOutcomeHeld MatchOutcome = "held"
)

// MatchRawFinding is the Matcher step of the Scanner pipeline (AGENTS.md
// §20): Scanner -> RawFinding -> Normalizer (rawfinding.Classify) ->
// Matcher (this function) -> Finding. It only handles the
// ClassificationKnownVulnerability case end-to-end (correlating to an
// existing Vulnerability via CorrelateFindings, AGENTS.md §26); the other
// two classifications, and creating a new Vulnerability record when a
// named CVE has no existing record, are deliberately out of scope (ADR
// 0016 "対象外") -- see MatchOutcomeHeld/MatchOutcomeUnmatched.
//
// Per AGENTS.md §20A.1 ("PownForge専用の特別経路を作らない"), this
// function has no PownForge-specific logic: rf is a generic RawFinding
// regardless of which Scanner produced it.
func (s *Service) MatchRawFinding(ctx context.Context, rf rawfinding.RawFinding) (*finding.Finding, MatchOutcome, error) {
	result := rawfinding.Classify(rf)
	if result.Classification != rawfinding.ClassificationKnownVulnerability {
		return nil, MatchOutcomeHeld, nil
	}

	v, err := s.Vulnerabilities.FindByCVE(ctx, result.VulnerabilityIdentifier)
	if err != nil {
		return nil, "", fmt.Errorf("application: find vulnerability by cve %s: %w", result.VulnerabilityIdentifier, err)
	}
	if v == nil {
		return nil, MatchOutcomeUnmatched, nil
	}

	f, err := s.CorrelateFindings(ctx, finding.Params{
		AssetID:         rf.AssetID,
		VulnerabilityID: v.ID,
		DetectionSource: rf.Source,
		DetectedAt:      rf.CollectedAt,
		Confidence:      rf.Confidence,
		EvidenceID:      string(rf.EvidenceID),
	})
	if err != nil {
		return nil, "", fmt.Errorf("application: correlate finding for rawfinding: %w", err)
	}
	return f, MatchOutcomeCorrelated, nil
}
