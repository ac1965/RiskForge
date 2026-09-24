package risk

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies a RiskAssessment.
type ID string

// NewID returns a new random RiskAssessment ID.
func NewID() ID {
	return ID(id.New())
}

// Assessment is the outcome of evaluating a Finding's risk (AGENTS.md §3,
// §8). It is a distinct entity from Finding, Vulnerability, and Priority
// (AGENTS.md §44 Invariants 1, 2, 5): Score is never the same value as
// CVSS, and a later PriorityDecision is a separate computation that
// merely takes this Assessment as one of its inputs.
type Assessment struct {
	ID            ID
	FindingID     finding.ID
	Score         float64
	Level         Level
	Factors       []explainability.Factor
	PolicyName    string
	PolicyVersion string
	AssessedAt    time.Time
}

// Params holds the fields needed to create a new Assessment.
type Params struct {
	FindingID     finding.ID
	Score         float64
	Level         Level
	Factors       []explainability.Factor
	PolicyName    string
	PolicyVersion string
	AssessedAt    time.Time
}

// New creates an Assessment from p, requiring at least one valid Factor so
// the score can always be explained (AGENTS.md §40).
func New(p Params) (*Assessment, error) {
	if strings.TrimSpace(string(p.FindingID)) == "" {
		return nil, fmt.Errorf("risk: finding id is required")
	}
	if p.Score < 0 || p.Score > 100 {
		return nil, fmt.Errorf("risk: score %v out of range [0,100]", p.Score)
	}
	if !p.Level.Valid() {
		return nil, fmt.Errorf("risk: invalid level %q", p.Level)
	}
	if len(p.Factors) == 0 {
		return nil, fmt.Errorf("risk: at least one factor is required for explainability")
	}
	for _, f := range p.Factors {
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("risk: %w", err)
		}
	}
	if strings.TrimSpace(p.PolicyName) == "" {
		return nil, fmt.Errorf("risk: policy name is required")
	}
	if p.AssessedAt.IsZero() {
		return nil, fmt.Errorf("risk: assessed at is required")
	}

	return &Assessment{
		ID:            NewID(),
		FindingID:     p.FindingID,
		Score:         p.Score,
		Level:         p.Level,
		Factors:       p.Factors,
		PolicyName:    p.PolicyName,
		PolicyVersion: p.PolicyVersion,
		AssessedAt:    p.AssessedAt,
	}, nil
}
