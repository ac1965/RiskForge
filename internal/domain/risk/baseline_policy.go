package risk

import (
	"fmt"
	"strings"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/explainability"
)

// BaselinePolicy is a simple, deterministic reference implementation of
// Policy. It exists so the Risk Engine is usable and testable out of the
// box; it is one Policy among possibly many (AGENTS.md §8), not "the"
// risk formula — a real deployment can supply its own Policy, and a
// configuration-driven Policy Engine is planned for Phase 4 (§23, §45).
type BaselinePolicy struct{}

var severityBaseScore = map[string]float64{
	"critical": 40,
	"high":     30,
	"medium":   20,
	"low":      10,
	"none":     0,
	"unknown":  5,
}

var assetCriticalityBonus = map[asset.Criticality]float64{
	asset.CriticalityCritical: 15,
	asset.CriticalityHigh:     10,
	asset.CriticalityMedium:   5,
	asset.CriticalityLow:      0,
	asset.CriticalityUnknown:  0,
}

// Name returns "baseline".
func (BaselinePolicy) Name() string { return "baseline" }

// Version returns the policy's version string.
func (BaselinePolicy) Version() string { return "1.0.0" }

// Evaluate scores in using a fixed set of weighted contributions. It is
// deliberately simple and fully explained via Result.Factors.
func (BaselinePolicy) Evaluate(in PolicyInput) (Result, error) {
	var score float64
	var factors []explainability.Factor

	base := severityBaseScore[string(in.Severity)]
	factors = append(factors, explainability.Factor{
		Name:   "severity",
		Value:  string(in.Severity),
		Reason: fmt.Sprintf("Vulnerability severity is %s", in.Severity),
	})
	if in.CVSSv3 != nil {
		if cvssScore := *in.CVSSv3 * 4; cvssScore > base {
			base = cvssScore
		}
		factors = append(factors, explainability.Factor{
			Name:   "cvss_v3",
			Value:  fmt.Sprintf("%.1f", *in.CVSSv3),
			Reason: fmt.Sprintf("CVSSv3 base score %.1f", *in.CVSSv3),
		})
	}
	score += base

	switch {
	case in.Exploitability.KEVListed:
		score += 25
		factors = append(factors, explainability.Factor{
			Name: "kev_listed", Value: "true",
			Reason: "CISA Known Exploited Vulnerabilities (KEV) listed",
		})
	case in.Exploitability.ExploitationObserved:
		score += 20
		factors = append(factors, explainability.Factor{
			Name: "exploitation_observed", Value: "true",
			Reason: "Exploitation observed in the wild",
		})
	case in.Exploitability.PublicExploit || in.Exploitability.ExploitCodeAvailable:
		score += 10
		factors = append(factors, explainability.Factor{
			Name: "public_exploit", Value: "true",
			Reason: "Public exploit code is available",
		})
	case in.Exploitability.ExploitExists:
		score += 5
		factors = append(factors, explainability.Factor{
			Name: "exploit_exists", Value: "true",
			Reason: "An exploit is known to exist",
		})
	}
	if in.Exploitability.ExploitPrediction != nil {
		pred := *in.Exploitability.ExploitPrediction
		score += pred * 15
		factors = append(factors, explainability.Factor{
			Name:   "exploit_prediction",
			Value:  fmt.Sprintf("%.0f%%", pred*100),
			Reason: fmt.Sprintf("Predicted exploitation probability %.0f%%", pred*100),
		})
	}

	switch {
	case in.Exposure.InternetExposed:
		score += 15
		factors = append(factors, explainability.Factor{
			Name: "exposure", Value: "internet_exposed", Reason: "Internet exposed",
		})
	case in.Exposure.ExternallyAccessible:
		score += 8
		factors = append(factors, explainability.Factor{
			Name: "exposure", Value: "externally_accessible", Reason: "Externally accessible",
		})
	case in.Exposure.ReachableFromUntrustedNetwork:
		score += 5
		factors = append(factors, explainability.Factor{
			Name: "exposure", Value: "reachable_from_untrusted_network", Reason: "Reachable from untrusted network",
		})
	}

	score += assetCriticalityBonus[in.AssetCriticality]
	factors = append(factors, explainability.Factor{
		Name:   "asset_criticality",
		Value:  string(in.AssetCriticality),
		Reason: fmt.Sprintf("Asset criticality: %s", in.AssetCriticality),
	})

	if bc := strings.ToLower(in.BusinessImpact.BusinessCriticality); bc == "critical" || bc == "high" {
		bonus := 5.0
		if bc == "critical" {
			bonus = 10
		}
		score += bonus
		factors = append(factors, explainability.Factor{
			Name:   "business_criticality",
			Value:  in.BusinessImpact.BusinessCriticality,
			Reason: fmt.Sprintf("Business criticality: %s", in.BusinessImpact.BusinessCriticality),
		})
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	var level Level
	switch {
	case score >= 85:
		level = LevelCritical
	case score >= 60:
		level = LevelHigh
	case score >= 30:
		level = LevelMedium
	default:
		level = LevelLow
	}

	return Result{Score: score, Level: level, Factors: factors}, nil
}
