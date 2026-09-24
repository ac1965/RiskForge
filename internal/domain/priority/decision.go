package priority

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/id"
	"github.com/ac1965/riskforge/internal/domain/risk"
)

// ID uniquely identifies a PriorityDecision.
type ID string

// NewID returns a new random PriorityDecision ID.
func NewID() ID {
	return ID(id.New())
}

// Decision is the outcome of deciding what to remediate first for a given
// Finding (AGENTS.md §3, §12). It references the RiskAssessment it was
// computed from but is itself a separate entity and computation
// (AGENTS.md §44 Invariant 2: Risk != Priority).
type Decision struct {
	ID               ID
	FindingID        finding.ID
	RiskAssessmentID risk.ID
	Rank             float64
	Level            Level
	Factors          []explainability.Factor
	SLADeadline      time.Time
	PolicyName       string
	PolicyVersion    string
	DecidedAt        time.Time
}

// Params holds the fields needed to create a new Decision.
type Params struct {
	FindingID        finding.ID
	RiskAssessmentID risk.ID
	Rank             float64
	Level            Level
	Factors          []explainability.Factor
	SLADeadline      time.Time
	PolicyName       string
	PolicyVersion    string
	DecidedAt        time.Time
}

// New creates a Decision from p, requiring at least one valid Factor so
// the ranking can always be explained (AGENTS.md §40).
func New(p Params) (*Decision, error) {
	if strings.TrimSpace(string(p.FindingID)) == "" {
		return nil, fmt.Errorf("priority: finding id is required")
	}
	if strings.TrimSpace(string(p.RiskAssessmentID)) == "" {
		return nil, fmt.Errorf("priority: risk assessment id is required")
	}
	if p.Rank < 0 || p.Rank > 100 {
		return nil, fmt.Errorf("priority: rank %v out of range [0,100]", p.Rank)
	}
	if !p.Level.Valid() {
		return nil, fmt.Errorf("priority: invalid level %q", p.Level)
	}
	if len(p.Factors) == 0 {
		return nil, fmt.Errorf("priority: at least one factor is required for explainability")
	}
	for _, f := range p.Factors {
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("priority: %w", err)
		}
	}
	if strings.TrimSpace(p.PolicyName) == "" {
		return nil, fmt.Errorf("priority: policy name is required")
	}
	if p.SLADeadline.IsZero() {
		return nil, fmt.Errorf("priority: sla deadline is required")
	}
	if p.DecidedAt.IsZero() {
		return nil, fmt.Errorf("priority: decided at is required")
	}

	return &Decision{
		ID:               NewID(),
		FindingID:        p.FindingID,
		RiskAssessmentID: p.RiskAssessmentID,
		Rank:             p.Rank,
		Level:            p.Level,
		Factors:          p.Factors,
		SLADeadline:      p.SLADeadline,
		PolicyName:       p.PolicyName,
		PolicyVersion:    p.PolicyVersion,
		DecidedAt:        p.DecidedAt,
	}, nil
}
