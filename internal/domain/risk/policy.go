package risk

import (
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// PolicyInput bundles the provider outputs a Policy needs to score a
// Finding's risk.
type PolicyInput struct {
	Severity         vulnerability.Severity
	CVSSv3           *float64
	CVSSv4           *float64
	Exploitability   Exploitability
	AssetCriticality asset.Criticality
	Exposure         asset.Exposure
	BusinessImpact   BusinessImpact
}

// Result is the score, level, and explanation a Policy produces for one
// PolicyInput.
type Result struct {
	Score   float64
	Level   Level
	Factors []explainability.Factor
}

// Policy computes a risk Score, Level, and explanation from gathered
// inputs (AGENTS.md §8). Risk must never be a single fixed multiplication
// hardcoded into the Engine — implementations of Policy are swappable,
// and a fully configuration-driven Policy Engine is planned for Phase 4
// (AGENTS.md §23, §45); this interface is what makes that later addition
// possible without changing the Engine.
type Policy interface {
	Name() string
	Version() string
	Evaluate(PolicyInput) (Result, error)
}
