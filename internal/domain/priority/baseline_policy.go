package priority

import (
	"fmt"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/explainability"
)

// BaselinePolicy is a simple, deterministic reference implementation of
// Policy. Like risk.BaselinePolicy, it is one Policy among possibly many
// (AGENTS.md §12), not "the" prioritization formula.
//
// It demonstrates AGENTS.md §12's example directly: starting from the
// same Risk score, it re-weights AssetCriticality and Exposure (so a
// production, internet-facing, business-critical asset ranks above an
// otherwise identical low-criticality internal one), and adjusts for
// RemediationAvailability and BusinessConstraints, which risk.Policy never
// sees.
type BaselinePolicy struct {
	// Now is used to evaluate BusinessConstraints.ComplianceDeadline
	// urgency. It defaults to time.Now when nil, and exists so tests can
	// supply a fixed clock.
	Now func() time.Time
}

var priorityAssetCriticalityBonus = map[asset.Criticality]float64{
	asset.CriticalityCritical: 10,
	asset.CriticalityHigh:     6,
	asset.CriticalityMedium:   3,
	asset.CriticalityLow:      0,
	asset.CriticalityUnknown:  0,
}

// Name returns "baseline".
func (BaselinePolicy) Name() string { return "baseline" }

// Version returns the policy's version string.
func (BaselinePolicy) Version() string { return "1.0.0" }

func (p BaselinePolicy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Evaluate ranks in using in.Risk.Score as a starting point, then applies
// AssetCriticality, Exposure, RemediationAvailable, and
// BusinessConstraints on top of it.
func (p BaselinePolicy) Evaluate(in PolicyInput) (Result, error) {
	if in.Risk == nil {
		return Result{}, fmt.Errorf("priority: policy input risk assessment is required")
	}

	rank := in.Risk.Score
	factors := []explainability.Factor{{
		Name:   "risk_score",
		Value:  fmt.Sprintf("%.1f", in.Risk.Score),
		Reason: fmt.Sprintf("Starting from risk score %.1f (%s)", in.Risk.Score, in.Risk.Level),
	}}

	if bonus := priorityAssetCriticalityBonus[in.AssetCriticality]; bonus > 0 {
		rank += bonus
		factors = append(factors, explainability.Factor{
			Name:   "asset_criticality",
			Value:  string(in.AssetCriticality),
			Reason: fmt.Sprintf("Asset criticality: %s", in.AssetCriticality),
		})
	}

	switch {
	case in.Exposure.InternetExposed:
		rank += 8
		factors = append(factors, explainability.Factor{
			Name: "exposure", Value: "internet_exposed", Reason: "Internet exposed",
		})
	case in.Exposure.ExternallyAccessible:
		rank += 4
		factors = append(factors, explainability.Factor{
			Name: "exposure", Value: "externally_accessible", Reason: "Externally accessible",
		})
	case in.Exposure.ReachableFromUntrustedNetwork:
		rank += 2
		factors = append(factors, explainability.Factor{
			Name: "exposure", Value: "reachable_from_untrusted_network", Reason: "Reachable from untrusted network",
		})
	}

	if in.RemediationAvailable {
		rank += 5
		factors = append(factors, explainability.Factor{
			Name: "remediation_available", Value: "true",
			Reason: "A remediation is available, so this finding is immediately actionable",
		})
	} else {
		rank -= 5
		factors = append(factors, explainability.Factor{
			Name: "remediation_available", Value: "false",
			Reason: "No remediation is available yet; requires a compensating control instead",
		})
	}

	if in.BusinessConstraints.ChangeFreeze {
		factors = append(factors, explainability.Factor{
			Name: "change_freeze", Value: "true",
			Reason: "A change freeze is in effect; execution may need to wait even though priority is unchanged",
		})
	}
	if dl := in.BusinessConstraints.ComplianceDeadline; dl != nil {
		if remaining := dl.Sub(p.now()); remaining > 0 && remaining <= 30*24*time.Hour {
			rank += 10
			factors = append(factors, explainability.Factor{
				Name:   "compliance_deadline",
				Value:  dl.Format(time.RFC3339),
				Reason: "A compliance deadline falls within 30 days",
			})
		}
	}

	if rank > 100 {
		rank = 100
	}
	if rank < 0 {
		rank = 0
	}

	var level Level
	switch {
	case rank >= 85:
		level = LevelCritical
	case rank >= 60:
		level = LevelHigh
	case rank >= 30:
		level = LevelMedium
	default:
		level = LevelLow
	}

	return Result{Rank: rank, Level: level, Factors: factors}, nil
}
