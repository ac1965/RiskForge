package priority

import "github.com/ac1965/riskforge/internal/domain/risk"

// Input bundles everything the Priority Engine needs to decide a
// Finding's priority. It embeds risk.Input so risk.ExploitabilityProvider,
// risk.AssetCriticalityProvider, and risk.ExposureProvider (AGENTS.md
// §12's Exploitability / AssetCriticality / Exposure inputs) can be reused
// as-is, without redefining equivalent interfaces here.
type Input struct {
	risk.Input
	RiskAssessment *risk.Assessment
}

// RemediationAvailabilityProvider reports whether a fix currently exists
// for the Finding's vulnerability (AGENTS.md §12).
type RemediationAvailabilityProvider interface {
	RemediationAvailability(Input) (bool, error)
}

// BusinessConstraintsProvider supplies operational constraints (change
// freezes, maintenance windows, compliance deadlines) that affect
// remediation ordering (AGENTS.md §12).
type BusinessConstraintsProvider interface {
	BusinessConstraints(Input) (BusinessConstraints, error)
}
