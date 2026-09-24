package finding

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/id"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// ID uniquely identifies a Finding.
type ID string

// NewID returns a new random Finding ID.
func NewID() ID {
	return ID(id.New())
}

// ErrInvalidTransition is returned by TransitionTo when the requested
// status change is not a valid move from the Finding's current status.
var ErrInvalidTransition = errors.New("finding: invalid status transition")

// validTransitions encodes the Finding lifecycle (AGENTS.md §16). Notably,
// StatusOpen and StatusMitigated cannot move directly to StatusVerified:
// a Finding can only be verified after being remediated, which is how
// "Detected != Verified Remediated" (AGENTS.md §44 Invariant 6) is
// enforced at the domain level.
var validTransitions = map[Status]map[Status]bool{
	StatusOpen: {
		StatusMitigated:     true,
		StatusRemediated:    true,
		StatusAccepted:      true,
		StatusFalsePositive: true,
	},
	StatusMitigated: {
		StatusRemediated:    true,
		StatusReopened:      true,
		StatusAccepted:      true,
		StatusFalsePositive: true,
	},
	StatusRemediated: {
		StatusVerified: true,
		StatusReopened: true,
	},
	StatusVerified: {
		StatusReopened: true,
	},
	StatusReopened: {
		StatusMitigated:     true,
		StatusRemediated:    true,
		StatusAccepted:      true,
		StatusFalsePositive: true,
	},
	StatusAccepted: {
		StatusReopened: true,
	},
	StatusFalsePositive: {
		StatusReopened: true,
	},
}

// Finding is the fact that a specific Vulnerability was detected on a
// specific Asset (AGENTS.md §7). It references both by ID and must never
// embed either directly (AGENTS.md §44 Invariant 1).
type Finding struct {
	ID              ID
	AssetID         asset.ID
	VulnerabilityID vulnerability.ID
	DetectionSource string
	DetectedAt      time.Time
	LastConfirmedAt time.Time
	Status          Status
	Confidence      Confidence
	EvidenceID      string
}

// Params holds the fields needed to create a new Finding.
type Params struct {
	AssetID         asset.ID
	VulnerabilityID vulnerability.ID
	DetectionSource string
	DetectedAt      time.Time
	Confidence      Confidence
	EvidenceID      string
}

// New creates a Finding from p. Every new Finding starts in StatusOpen:
// the initial detection of a vulnerability on an asset. Use TransitionTo
// to move it through its lifecycle.
func New(p Params) (*Finding, error) {
	if strings.TrimSpace(string(p.AssetID)) == "" {
		return nil, fmt.Errorf("finding: asset id is required")
	}
	if strings.TrimSpace(string(p.VulnerabilityID)) == "" {
		return nil, fmt.Errorf("finding: vulnerability id is required")
	}
	if strings.TrimSpace(p.DetectionSource) == "" {
		return nil, fmt.Errorf("finding: detection source is required")
	}
	if p.DetectedAt.IsZero() {
		return nil, fmt.Errorf("finding: detected at is required")
	}
	if !p.Confidence.Valid() {
		return nil, fmt.Errorf("finding: invalid confidence %q", p.Confidence)
	}

	return &Finding{
		ID:              NewID(),
		AssetID:         p.AssetID,
		VulnerabilityID: p.VulnerabilityID,
		DetectionSource: p.DetectionSource,
		DetectedAt:      p.DetectedAt,
		LastConfirmedAt: p.DetectedAt,
		Status:          StatusOpen,
		Confidence:      p.Confidence,
		EvidenceID:      p.EvidenceID,
	}, nil
}

// Confirm records that the finding was re-observed at t, advancing
// LastConfirmedAt without ever moving it backwards (AGENTS.md §37
// idempotency).
func (f *Finding) Confirm(t time.Time) error {
	if t.Before(f.DetectedAt) {
		return fmt.Errorf("finding: confirmed time (%s) precedes detected at (%s)", t, f.DetectedAt)
	}
	if t.After(f.LastConfirmedAt) {
		f.LastConfirmedAt = t
	}
	return nil
}

// TransitionTo moves the Finding to next, enforcing the lifecycle defined
// in validTransitions. Transitioning to the current status is a no-op.
func (f *Finding) TransitionTo(next Status) error {
	if !next.Valid() {
		return fmt.Errorf("finding: invalid status %q", next)
	}
	if f.Status == next {
		return nil
	}
	if !validTransitions[f.Status][next] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, f.Status, next)
	}
	f.Status = next
	return nil
}
