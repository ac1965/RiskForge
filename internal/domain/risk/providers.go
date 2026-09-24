package risk

import (
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// Input bundles everything the Risk Engine needs to assess one Finding.
type Input struct {
	Finding       *finding.Finding
	Asset         *asset.Asset
	Vulnerability *vulnerability.Vulnerability
}

// SeverityProvider supplies the vulnerability's technical severity
// (AGENTS.md §8). A concrete implementation may simply read
// Vulnerability.Severity, or recompute it (e.g. from CVSS vectors).
type SeverityProvider interface {
	Severity(Input) (vulnerability.Severity, error)
}

// ExploitabilityProvider supplies threat intelligence about the
// vulnerability at assessment time (AGENTS.md §8, §9). A concrete
// implementation typically enriches Vulnerability's static fields with
// live data from a CISA KEV / EPSS feed.
type ExploitabilityProvider interface {
	Exploitability(Input) (Exploitability, error)
}

// AssetCriticalityProvider supplies the asset's business criticality
// (AGENTS.md §8, §11). A concrete implementation may read
// Asset.Criticality, or look it up from a CMDB.
type AssetCriticalityProvider interface {
	AssetCriticality(Input) (asset.Criticality, error)
}

// ExposureProvider supplies how reachable the asset is by an attacker
// (AGENTS.md §8, §10).
type ExposureProvider interface {
	Exposure(Input) (asset.Exposure, error)
}

// BusinessImpactProvider supplies business-context inputs sourced from a
// CMDB, asset register, or business owner (AGENTS.md §8, §11).
type BusinessImpactProvider interface {
	BusinessImpact(Input) (BusinessImpact, error)
}
