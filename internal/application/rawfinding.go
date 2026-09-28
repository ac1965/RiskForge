package application

import (
	"context"
	"fmt"
	"strings"

	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
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
	// MatchOutcomeRegistered means rf had no CVE
	// (ClassificationUnknownVulnerability) and was registered as a new
	// CVE-less Vulnerability (or matched an existing one registered from
	// an earlier detection of the same issue, AGENTS.md §20A.2 case 2),
	// with a Finding created or confirmed for it.
	MatchOutcomeRegistered MatchOutcome = "registered"
	// MatchOutcomeHeld means rawfinding.Classify returned
	// ClassificationUnclassified (AGENTS.md §20A.2 case 3) -- persisting a
	// held RawFinding for later review is out of scope here (ADR 0016/0017
	// "対象外"); rf is neither discarded nor actioned.
	MatchOutcomeHeld MatchOutcome = "held"
)

// MatchRawFinding is the Matcher step of the Scanner pipeline (AGENTS.md
// §20): Scanner -> RawFinding -> Normalizer (rawfinding.Classify) ->
// Matcher (this function) -> Finding.
//
// Per AGENTS.md §20A.1 ("PownForge専用の特別経路を作らない"), this
// function has no PownForge-specific logic: rf is a generic RawFinding
// regardless of which Scanner produced it.
func (s *Service) MatchRawFinding(ctx context.Context, rf rawfinding.RawFinding) (*finding.Finding, MatchOutcome, error) {
	result := rawfinding.Classify(rf)

	switch result.Classification {
	case rawfinding.ClassificationKnownVulnerability:
		return s.matchKnownVulnerability(ctx, rf, result.VulnerabilityIdentifier)
	case rawfinding.ClassificationUnknownVulnerability:
		return s.matchUnknownVulnerability(ctx, rf)
	default: // ClassificationUnclassified
		return nil, MatchOutcomeHeld, nil
	}
}

// matchKnownVulnerability handles AGENTS.md §20A.2 case 1: rf named a CVE.
// Creating a new Vulnerability record when that CVE has no existing record
// yet is deliberately out of scope (ADR 0016 "対象外") -- see
// MatchOutcomeUnmatched.
func (s *Service) matchKnownVulnerability(ctx context.Context, rf rawfinding.RawFinding, cveID string) (*finding.Finding, MatchOutcome, error) {
	v, err := s.Vulnerabilities.FindByCVE(ctx, cveID)
	if err != nil {
		return nil, "", fmt.Errorf("application: find vulnerability by cve %s: %w", cveID, err)
	}
	if v == nil {
		return nil, MatchOutcomeUnmatched, nil
	}

	f, err := s.correlateRawFinding(ctx, rf, v.ID)
	if err != nil {
		return nil, "", err
	}
	return f, MatchOutcomeCorrelated, nil
}

// matchUnknownVulnerability handles AGENTS.md §20A.2 case 2: rf describes a
// real vulnerability (ADR 0015's Classify already required decent
// Confidence for this classification) with no CVE. It is registered under
// its own id, keyed by (Source, Title) for idempotency across repeated
// detections of the same issue (see ADR 0017 for why Title, not
// RawFinding.SourceRef, is used as the source_id).
func (s *Service) matchUnknownVulnerability(ctx context.Context, rf rawfinding.RawFinding) (*finding.Finding, MatchOutcome, error) {
	v, err := s.Vulnerabilities.FindByProvenanceSourceID(ctx, rf.Source, rf.Title)
	if err != nil {
		return nil, "", fmt.Errorf("application: find vulnerability by provenance %s/%s: %w", rf.Source, rf.Title, err)
	}
	if v == nil {
		v, err = vulnerability.New(vulnerability.Params{
			Title:       rf.Title,
			Description: rf.Detail,
			Severity:    severityFromRawFinding(rf),
			CVSSv3:      rf.CVSSScore,
			PublishedAt: rf.CollectedAt,
			Provenance: vulnerability.Provenance{
				Source:      rf.Source,
				SourceID:    rf.Title,
				RetrievedAt: rf.CollectedAt,
			},
		})
		if err != nil {
			return nil, "", fmt.Errorf("application: register vulnerability from rawfinding: %w", err)
		}
		if err := s.Vulnerabilities.Save(ctx, v); err != nil {
			return nil, "", fmt.Errorf("application: save registered vulnerability %s: %w", v.ID, err)
		}
	}

	f, err := s.correlateRawFinding(ctx, rf, v.ID)
	if err != nil {
		return nil, "", err
	}
	return f, MatchOutcomeRegistered, nil
}

func (s *Service) correlateRawFinding(ctx context.Context, rf rawfinding.RawFinding, vulnID vulnerability.ID) (*finding.Finding, error) {
	f, err := s.CorrelateFindings(ctx, finding.Params{
		AssetID:         rf.AssetID,
		VulnerabilityID: vulnID,
		DetectionSource: rf.Source,
		DetectedAt:      rf.CollectedAt,
		Confidence:      rf.Confidence,
		EvidenceID:      string(rf.EvidenceID),
	})
	if err != nil {
		return nil, fmt.Errorf("application: correlate finding for rawfinding: %w", err)
	}
	return f, nil
}

// severityFromRawFinding maps rf's NativeSeverity (a tool-reported label,
// e.g. PownForge's own Finding.native_severity -- see
// docs/adr/0005-pownforge-integration.md's field mapping) onto
// vulnerability.Severity. It deliberately does not fall back to a guessed
// default: SeverityUnknown is a real, already-used value in this codebase
// (it's `riskforge vulnerability`'s own --severity default), and the Risk
// Engine already scores it as a small-but-nonzero baseline
// (severityBaseScore["unknown"] = 5, internal/domain/risk/baseline_policy.go)
// distinct from a genuinely assessed low/none. CVSSv3 is passed through on
// Vulnerability separately: the Risk Engine takes whichever of Severity or
// CVSSv3*4 is higher, so this mapping does not need to fold CVSS into the
// Severity label itself (see ADR 0017).
func severityFromRawFinding(rf rawfinding.RawFinding) vulnerability.Severity {
	switch strings.ToLower(rf.NativeSeverity) {
	case "critical":
		return vulnerability.SeverityCritical
	case "high":
		return vulnerability.SeverityHigh
	case "medium":
		return vulnerability.SeverityMedium
	case "low":
		return vulnerability.SeverityLow
	case "info":
		// nuclei's only severity level with no RiskForge equivalent: an
		// "info" template documents a discovery, not a weakness (e.g. the
		// robots.txt prober PownForge's golden file test captures) --
		// SeverityNone ("no severity"), not SeverityLow, is the honest
		// mapping.
		return vulnerability.SeverityNone
	default:
		return vulnerability.SeverityUnknown
	}
}
