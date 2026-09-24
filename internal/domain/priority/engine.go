package priority

import (
	"fmt"
	"time"

	"github.com/ac1965/riskforge/internal/domain/risk"
)

// Engine composes independent providers, a Policy, and an SLAPolicy to
// turn an Input into a PriorityDecision (AGENTS.md §12). As with
// risk.Engine, no ranking logic lives here — it only gathers Provider
// outputs and hands them to Policy.
type Engine struct {
	Exploitability          risk.ExploitabilityProvider
	AssetCriticality        risk.AssetCriticalityProvider
	Exposure                risk.ExposureProvider
	RemediationAvailability RemediationAvailabilityProvider
	BusinessConstraints     BusinessConstraintsProvider
	Policy                  Policy
	SLAPolicy               SLAPolicy
}

// NewEngine creates an Engine, requiring every provider, the policy, and
// the SLA policy to be set.
func NewEngine(
	exploitability risk.ExploitabilityProvider,
	assetCriticality risk.AssetCriticalityProvider,
	exposure risk.ExposureProvider,
	remediationAvailability RemediationAvailabilityProvider,
	businessConstraints BusinessConstraintsProvider,
	policy Policy,
	slaPolicy SLAPolicy,
) (*Engine, error) {
	switch {
	case exploitability == nil:
		return nil, fmt.Errorf("priority: exploitability provider is required")
	case assetCriticality == nil:
		return nil, fmt.Errorf("priority: asset criticality provider is required")
	case exposure == nil:
		return nil, fmt.Errorf("priority: exposure provider is required")
	case remediationAvailability == nil:
		return nil, fmt.Errorf("priority: remediation availability provider is required")
	case businessConstraints == nil:
		return nil, fmt.Errorf("priority: business constraints provider is required")
	case policy == nil:
		return nil, fmt.Errorf("priority: policy is required")
	case slaPolicy == nil:
		return nil, fmt.Errorf("priority: sla policy is required")
	}

	return &Engine{
		Exploitability:          exploitability,
		AssetCriticality:        assetCriticality,
		Exposure:                exposure,
		RemediationAvailability: remediationAvailability,
		BusinessConstraints:     businessConstraints,
		Policy:                  policy,
		SLAPolicy:               slaPolicy,
	}, nil
}

// Decide gathers every provider's output for in and delegates ranking to
// the Engine's Policy, returning the resulting Decision.
func (e *Engine) Decide(in Input) (*Decision, error) {
	if in.Finding == nil {
		return nil, fmt.Errorf("priority: input finding is required")
	}
	if in.Asset == nil {
		return nil, fmt.Errorf("priority: input asset is required")
	}
	if in.Vulnerability == nil {
		return nil, fmt.Errorf("priority: input vulnerability is required")
	}
	if in.RiskAssessment == nil {
		return nil, fmt.Errorf("priority: input risk assessment is required")
	}
	if in.Finding.AssetID != in.Asset.ID {
		return nil, fmt.Errorf("priority: finding asset id %q does not match asset id %q", in.Finding.AssetID, in.Asset.ID)
	}
	if in.Finding.VulnerabilityID != in.Vulnerability.ID {
		return nil, fmt.Errorf("priority: finding vulnerability id %q does not match vulnerability id %q", in.Finding.VulnerabilityID, in.Vulnerability.ID)
	}
	if in.RiskAssessment.FindingID != in.Finding.ID {
		return nil, fmt.Errorf("priority: risk assessment finding id %q does not match finding id %q", in.RiskAssessment.FindingID, in.Finding.ID)
	}

	exploitability, err := e.Exploitability.Exploitability(in.Input)
	if err != nil {
		return nil, fmt.Errorf("priority: exploitability provider: %w", err)
	}
	assetCriticality, err := e.AssetCriticality.AssetCriticality(in.Input)
	if err != nil {
		return nil, fmt.Errorf("priority: asset criticality provider: %w", err)
	}
	exposure, err := e.Exposure.Exposure(in.Input)
	if err != nil {
		return nil, fmt.Errorf("priority: exposure provider: %w", err)
	}
	remediationAvailable, err := e.RemediationAvailability.RemediationAvailability(in)
	if err != nil {
		return nil, fmt.Errorf("priority: remediation availability provider: %w", err)
	}
	businessConstraints, err := e.BusinessConstraints.BusinessConstraints(in)
	if err != nil {
		return nil, fmt.Errorf("priority: business constraints provider: %w", err)
	}

	result, err := e.Policy.Evaluate(PolicyInput{
		Risk:                 in.RiskAssessment,
		AssetCriticality:     assetCriticality,
		Exposure:             exposure,
		Exploitability:       exploitability,
		RemediationAvailable: remediationAvailable,
		BusinessConstraints:  businessConstraints,
	})
	if err != nil {
		return nil, fmt.Errorf("priority: policy %q: %w", e.Policy.Name(), err)
	}

	deadline, err := e.SLAPolicy.Deadline(result.Level, in.Finding.DetectedAt)
	if err != nil {
		return nil, fmt.Errorf("priority: sla policy: %w", err)
	}

	return New(Params{
		FindingID:        in.Finding.ID,
		RiskAssessmentID: in.RiskAssessment.ID,
		Rank:             result.Rank,
		Level:            result.Level,
		Factors:          result.Factors,
		SLADeadline:      deadline,
		PolicyName:       e.Policy.Name(),
		PolicyVersion:    e.Policy.Version(),
		DecidedAt:        time.Now(),
	})
}
