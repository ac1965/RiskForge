package risk

import (
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// FromVulnerabilityProvider is a SeverityProvider and
// ExploitabilityProvider that reads directly from the Vulnerability
// already attached to the Input, with no external lookups. It is a
// reasonable default until an infrastructure adapter enriches
// Exploitability with live KEV/EPSS data (AGENTS.md §19).
type FromVulnerabilityProvider struct{}

// Severity returns in.Vulnerability.Severity.
func (FromVulnerabilityProvider) Severity(in Input) (vulnerability.Severity, error) {
	return in.Vulnerability.Severity, nil
}

// Exploitability derives an Exploitability snapshot from
// in.Vulnerability's own static fields. KEVListed and ExploitPrediction
// are left at their zero values since Vulnerability does not carry live
// threat intel; a richer provider can override this.
func (FromVulnerabilityProvider) Exploitability(in Input) (Exploitability, error) {
	return Exploitability{
		ExploitExists:        in.Vulnerability.ExploitAvailable,
		ExploitationObserved: in.Vulnerability.ExploitationObserved,
	}, nil
}

// FromAssetProvider is an AssetCriticalityProvider and ExposureProvider
// that reads directly from the Asset already attached to the Input.
type FromAssetProvider struct{}

// AssetCriticality returns in.Asset.Criticality.
func (FromAssetProvider) AssetCriticality(in Input) (asset.Criticality, error) {
	return in.Asset.Criticality, nil
}

// Exposure returns in.Asset.Exposure.
func (FromAssetProvider) Exposure(in Input) (asset.Exposure, error) {
	return in.Asset.Exposure, nil
}

// StaticBusinessImpactProvider always returns the same BusinessImpact,
// regardless of Input. It is a placeholder for use until a CMDB adapter
// is wired in (AGENTS.md §11): real business impact should come from
// business context, not be hardcoded.
type StaticBusinessImpactProvider struct {
	Impact BusinessImpact
}

// BusinessImpact returns p.Impact.
func (p StaticBusinessImpactProvider) BusinessImpact(Input) (BusinessImpact, error) {
	return p.Impact, nil
}
