package risk

import (
	"fmt"
	"time"
)

// Engine composes independent providers and a Policy to turn an Input into
// a RiskAssessment (AGENTS.md §8). None of the scoring logic lives here:
// the Engine only gathers Provider outputs and hands them to Policy.
type Engine struct {
	Severity         SeverityProvider
	Exploitability   ExploitabilityProvider
	AssetCriticality AssetCriticalityProvider
	Exposure         ExposureProvider
	BusinessImpact   BusinessImpactProvider
	Policy           Policy
}

// NewEngine creates an Engine, requiring every provider and the policy to
// be set.
func NewEngine(
	severity SeverityProvider,
	exploitability ExploitabilityProvider,
	assetCriticality AssetCriticalityProvider,
	exposure ExposureProvider,
	businessImpact BusinessImpactProvider,
	policy Policy,
) (*Engine, error) {
	switch {
	case severity == nil:
		return nil, fmt.Errorf("risk: severity provider is required")
	case exploitability == nil:
		return nil, fmt.Errorf("risk: exploitability provider is required")
	case assetCriticality == nil:
		return nil, fmt.Errorf("risk: asset criticality provider is required")
	case exposure == nil:
		return nil, fmt.Errorf("risk: exposure provider is required")
	case businessImpact == nil:
		return nil, fmt.Errorf("risk: business impact provider is required")
	case policy == nil:
		return nil, fmt.Errorf("risk: policy is required")
	}

	return &Engine{
		Severity:         severity,
		Exploitability:   exploitability,
		AssetCriticality: assetCriticality,
		Exposure:         exposure,
		BusinessImpact:   businessImpact,
		Policy:           policy,
	}, nil
}

// Assess gathers every provider's output for in and delegates scoring to
// the Engine's Policy, returning the resulting Assessment.
func (e *Engine) Assess(in Input) (*Assessment, error) {
	if in.Finding == nil {
		return nil, fmt.Errorf("risk: input finding is required")
	}
	if in.Asset == nil {
		return nil, fmt.Errorf("risk: input asset is required")
	}
	if in.Vulnerability == nil {
		return nil, fmt.Errorf("risk: input vulnerability is required")
	}
	if in.Finding.AssetID != in.Asset.ID {
		return nil, fmt.Errorf("risk: finding asset id %q does not match asset id %q", in.Finding.AssetID, in.Asset.ID)
	}
	if in.Finding.VulnerabilityID != in.Vulnerability.ID {
		return nil, fmt.Errorf("risk: finding vulnerability id %q does not match vulnerability id %q", in.Finding.VulnerabilityID, in.Vulnerability.ID)
	}

	severity, err := e.Severity.Severity(in)
	if err != nil {
		return nil, fmt.Errorf("risk: severity provider: %w", err)
	}
	exploitability, err := e.Exploitability.Exploitability(in)
	if err != nil {
		return nil, fmt.Errorf("risk: exploitability provider: %w", err)
	}
	assetCriticality, err := e.AssetCriticality.AssetCriticality(in)
	if err != nil {
		return nil, fmt.Errorf("risk: asset criticality provider: %w", err)
	}
	exposure, err := e.Exposure.Exposure(in)
	if err != nil {
		return nil, fmt.Errorf("risk: exposure provider: %w", err)
	}
	businessImpact, err := e.BusinessImpact.BusinessImpact(in)
	if err != nil {
		return nil, fmt.Errorf("risk: business impact provider: %w", err)
	}

	result, err := e.Policy.Evaluate(PolicyInput{
		Severity:         severity,
		CVSSv3:           in.Vulnerability.CVSSv3,
		CVSSv4:           in.Vulnerability.CVSSv4,
		Exploitability:   exploitability,
		AssetCriticality: assetCriticality,
		Exposure:         exposure,
		BusinessImpact:   businessImpact,
	})
	if err != nil {
		return nil, fmt.Errorf("risk: policy %q: %w", e.Policy.Name(), err)
	}

	return New(Params{
		FindingID:     in.Finding.ID,
		Score:         result.Score,
		Level:         result.Level,
		Factors:       result.Factors,
		PolicyName:    e.Policy.Name(),
		PolicyVersion: e.Policy.Version(),
		AssessedAt:    time.Now(),
	})
}
