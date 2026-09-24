package priority

import (
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/risk"
)

// PolicyInput bundles the provider outputs a Policy needs to rank a
// Finding's priority (AGENTS.md §12).
type PolicyInput struct {
	Risk                 *risk.Assessment
	AssetCriticality     asset.Criticality
	Exposure             asset.Exposure
	Exploitability       risk.Exploitability
	RemediationAvailable bool
	BusinessConstraints  BusinessConstraints
}

// Result is the rank, level, and explanation a Policy produces for one
// PolicyInput.
type Result struct {
	Rank    float64
	Level   Level
	Factors []explainability.Factor
}

// Policy computes a priority Rank, Level, and explanation from gathered
// inputs (AGENTS.md §12). Like risk.Policy, it is deliberately pluggable:
// the same Risk score can lead to different priorities depending on
// AssetCriticality, Exposure, and BusinessConstraints, and that
// combination logic must not be hardcoded into the Engine.
type Policy interface {
	Name() string
	Version() string
	Evaluate(PolicyInput) (Result, error)
}
