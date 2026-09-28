package rawfinding

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies a RawFinding.
type ID string

// NewID returns a new random RawFinding ID.
func NewID() ID {
	return ID(id.New())
}

// RawFinding is a Scanner's raw observation, before Normalizer
// classification and Matcher correlation to an existing Vulnerability
// (AGENTS.md §20, §20A). It has no setters, matching Evidence's immutable,
// append-only treatment (AGENTS.md §22, §47.10): a corrected observation is
// a new RawFinding, never a mutation of an existing one.
type RawFinding struct {
	ID        ID
	Source    string // the Scanner, e.g. "pownforge:nuclei" (AGENTS.md §20A.1)
	SourceRef string // the source's own identifier for this observation, used for idempotency (AGENTS.md §20A.7)
	AssetID   asset.ID
	// EvidenceID is optional: not every RawFinding is backed by a
	// separately-stored Evidence record at creation time (AGENTS.md §20A.4
	// describes the same "collected before correlation" allowance evidence.Evidence
	// already makes for FindingID).
	EvidenceID evidence.ID
	Title      string
	Detail     string
	Confidence finding.Confidence
	// CVSSScore/CVSSVector/NativeSeverity/AttackTechniqueIDs are optional
	// pass-through evidence from the Scanner (e.g. PownForge's own Finding
	// fields, see docs/adr/0005-pownforge-integration.md's field mapping).
	// RawFinding only carries them -- deciding whether/how they influence
	// the eventual Vulnerability/Finding is the Matcher's job, not this
	// package's (see doc.go).
	CVSSScore          *float64
	CVSSVector         string
	NativeSeverity     string
	AttackTechniqueIDs []string
	CollectedAt        time.Time
}

// Params holds the fields needed to create a new RawFinding.
type Params struct {
	Source             string
	SourceRef          string
	AssetID            asset.ID
	EvidenceID         evidence.ID
	Title              string
	Detail             string
	Confidence         finding.Confidence
	CVSSScore          *float64
	CVSSVector         string
	NativeSeverity     string
	AttackTechniqueIDs []string
	CollectedAt        time.Time
}

// New creates a RawFinding from p, validating required fields.
func New(p Params) (*RawFinding, error) {
	if strings.TrimSpace(p.Source) == "" {
		return nil, fmt.Errorf("rawfinding: source is required")
	}
	if strings.TrimSpace(string(p.AssetID)) == "" {
		return nil, fmt.Errorf("rawfinding: asset id is required")
	}
	if strings.TrimSpace(p.Title) == "" {
		return nil, fmt.Errorf("rawfinding: title is required")
	}
	if p.Confidence == "" {
		p.Confidence = finding.ConfidenceUnknown
	}
	if !p.Confidence.Valid() {
		return nil, fmt.Errorf("rawfinding: invalid confidence %q", p.Confidence)
	}
	if p.CollectedAt.IsZero() {
		return nil, fmt.Errorf("rawfinding: collected at is required")
	}

	return &RawFinding{
		ID:                 NewID(),
		Source:             p.Source,
		SourceRef:          p.SourceRef,
		AssetID:            p.AssetID,
		EvidenceID:         p.EvidenceID,
		Title:              p.Title,
		Detail:             p.Detail,
		Confidence:         p.Confidence,
		CVSSScore:          p.CVSSScore,
		CVSSVector:         p.CVSSVector,
		NativeSeverity:     p.NativeSeverity,
		AttackTechniqueIDs: p.AttackTechniqueIDs,
		CollectedAt:        p.CollectedAt,
	}, nil
}
