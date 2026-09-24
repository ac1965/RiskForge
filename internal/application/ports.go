package application

import (
	"context"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/remediation"
	"github.com/ac1965/riskforge/internal/domain/risk"
	"github.com/ac1965/riskforge/internal/domain/software"
	"github.com/ac1965/riskforge/internal/domain/verification"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// This file defines the ports (repository interfaces) the Named APIs need
// for persistence. Application defines them and Infrastructure implements
// them (AGENTS.md §25 Layering): Domain never sees these, and Application
// never imports a database driver directly. A "not found" lookup returns
// (nil, nil), not an error — callers check for a nil result.

// AssetRepository persists and retrieves Assets.
type AssetRepository interface {
	Save(ctx context.Context, a *asset.Asset) error
	FindByID(ctx context.Context, id asset.ID) (*asset.Asset, error)
	// FindByHostname is the idempotency key for DiscoverAssets (AGENTS.md
	// §37): repeated discovery of the same host must update, not
	// duplicate, its Asset record.
	FindByHostname(ctx context.Context, hostname string) (*asset.Asset, error)
}

// SoftwareRepository persists and retrieves SoftwareInstallations.
type SoftwareRepository interface {
	Save(ctx context.Context, i *software.Installation) error
	// FindByNaturalKey is InventoryAsset's idempotency key (AGENTS.md
	// §37): the same package observed again on the same asset updates
	// LastSeen instead of creating a duplicate installation record.
	FindByNaturalKey(ctx context.Context, assetID asset.ID, vendor, product, version string) (*software.Installation, error)
}

// VulnerabilityRepository persists and retrieves Vulnerabilities.
type VulnerabilityRepository interface {
	Save(ctx context.Context, v *vulnerability.Vulnerability) error
	FindByID(ctx context.Context, id vulnerability.ID) (*vulnerability.Vulnerability, error)
}

// FindingRepository persists and retrieves Findings.
type FindingRepository interface {
	Save(ctx context.Context, f *finding.Finding) error
	FindByID(ctx context.Context, id finding.ID) (*finding.Finding, error)
	// FindByAssetAndVulnerability is CorrelateFindings's idempotency key
	// (AGENTS.md §37): re-detecting the same vulnerability on the same
	// asset confirms the existing Finding instead of creating a
	// duplicate.
	FindByAssetAndVulnerability(ctx context.Context, assetID asset.ID, vulnID vulnerability.ID) (*finding.Finding, error)
}

// RiskAssessmentRepository persists and retrieves RiskAssessments.
type RiskAssessmentRepository interface {
	Save(ctx context.Context, a *risk.Assessment) error
	FindLatestByFinding(ctx context.Context, findingID finding.ID) (*risk.Assessment, error)
}

// PriorityDecisionRepository persists and retrieves PriorityDecisions.
type PriorityDecisionRepository interface {
	Save(ctx context.Context, d *priority.Decision) error
	FindLatestByFinding(ctx context.Context, findingID finding.ID) (*priority.Decision, error)
}

// RemediationPlanRepository persists and retrieves RemediationPlans.
type RemediationPlanRepository interface {
	Save(ctx context.Context, p *remediation.Plan) error
	FindByID(ctx context.Context, id remediation.ID) (*remediation.Plan, error)
}

// VerificationRepository persists Verifications.
type VerificationRepository interface {
	Save(ctx context.Context, v *verification.Verification) error
}

// EvidenceRepository persists and retrieves Evidence.
type EvidenceRepository interface {
	Save(ctx context.Context, e *evidence.Evidence) error
	FindByID(ctx context.Context, id evidence.ID) (*evidence.Evidence, error)
}

// ExceptionRepository persists and retrieves Exceptions.
type ExceptionRepository interface {
	Save(ctx context.Context, e *exception.Exception) error
	FindByID(ctx context.Context, id exception.ID) (*exception.Exception, error)
}

// AuditRepository appends audit.Entry records. There is deliberately no
// update or delete method (AGENTS.md §30, mirroring §22/§47.10 for
// Evidence): an audit trail that could be edited after the fact would
// defeat its purpose.
type AuditRepository interface {
	Save(ctx context.Context, e *audit.Entry) error
}

// RemediationExecutor performs the actual, infrastructure-level change a
// RemediationPlan describes (the validated, structured,
// allowlist-checked command execution required by AGENTS.md §31, §32).
// No implementation exists yet — providing one is Infrastructure's job in
// a later phase; ExecuteRemediation only defines the seam.
type RemediationExecutor interface {
	Execute(ctx context.Context, plan *remediation.Plan, target remediation.DryRunInput) error
}
