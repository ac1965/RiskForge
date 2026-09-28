package rawfinding

import (
	"regexp"
	"strings"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

// Classification is the Normalizer's three-way split of a RawFinding
// (AGENTS.md §20A.2).
type Classification string

const (
	// ClassificationKnownVulnerability means the RawFinding names a
	// recognizable existing-Vulnerability identifier (currently: a CVE ID).
	// Whether that identifier actually matches a Vulnerability record in
	// this RiskForge instance is the Matcher's job, not this package's.
	ClassificationKnownVulnerability Classification = "known_vulnerability"
	// ClassificationUnknownVulnerability means the RawFinding describes a
	// real vulnerability with enough Confidence to register, but carries no
	// CVE (AGENTS.md §20A.2 case 2: "CVEを持たないVulnerabilityとして登録
	// する(独自ID、CWEのみ等)"). Source+SourceRef (already required/present
	// on RawFinding) is the source_id record §20A.2 requires for it.
	ClassificationUnknownVulnerability Classification = "unknown_vulnerability"
	// ClassificationUnclassified means neither of the above could be
	// determined confidently; the RawFinding is held rather than discarded
	// (AGENTS.md §20A.2 case 3).
	ClassificationUnclassified Classification = "unclassified"
)

// Valid reports whether c is one of the defined classifications.
func (c Classification) Valid() bool {
	switch c {
	case ClassificationKnownVulnerability, ClassificationUnknownVulnerability, ClassificationUnclassified:
		return true
	}
	return false
}

// cveIDPattern matches a CVE identifier (case-insensitive) anywhere in a
// RawFinding's Title or Detail. PownForge's own scanners (trivy/grype/
// nuclei/vulncheck) all embed the CVE this way rather than exposing it as
// a separate structured field (see docs/adr/0005-pownforge-integration.md),
// so extracting it here -- interpreting a loosely-structured Scanner
// result -- is Normalizer work, not something the Adapter must pre-parse.
var cveIDPattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// ClassificationResult is Classify's outcome: the three-way split, plus the
// CVE identifier extracted for ClassificationKnownVulnerability (empty
// otherwise).
type ClassificationResult struct {
	Classification          Classification
	VulnerabilityIdentifier string
}

// Classify implements the AGENTS.md §20A.2 three-way split for rf. It never
// queries a repository: it only inspects rf's own fields, exactly as
// AGENTS.md §20A.1 requires ("PownForge専用の特別経路を作らない") -- this
// logic is identical regardless of which Scanner produced rf.
func Classify(rf RawFinding) ClassificationResult {
	if cve := cveIDPattern.FindString(rf.Title + " " + rf.Detail); cve != "" {
		return ClassificationResult{
			Classification:          ClassificationKnownVulnerability,
			VulnerabilityIdentifier: strings.ToUpper(cve),
		}
	}

	switch rf.Confidence {
	case finding.ConfidenceLow, finding.ConfidenceUnknown, "":
		return ClassificationResult{Classification: ClassificationUnclassified}
	default:
		return ClassificationResult{Classification: ClassificationUnknownVulnerability}
	}
}
