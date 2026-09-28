package application

import (
	"context"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/authn"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
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
	// List returns every Asset, for `riskforge asset list` (AGENTS.md §27).
	List(ctx context.Context) ([]*asset.Asset, error)
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
	// FindByCVE is MatchRawFinding's lookup key (ADR 0016) for a RawFinding
	// the Normalizer classified as ClassificationKnownVulnerability: it
	// looks for an existing Vulnerability record for the extracted CVE
	// id. Returns (nil, nil), not an error, when no such Vulnerability is
	// registered yet -- creating one from scratch is not this port's job
	// (see ADR 0016 "対象外").
	FindByCVE(ctx context.Context, cveID string) (*vulnerability.Vulnerability, error)
	// FindByProvenanceSourceID is MatchRawFinding's idempotency key (ADR
	// 0017) for the ClassificationUnknownVulnerability case (AGENTS.md
	// §20A.2 case 2, "独自IDのVulnerabilityとして登録する... sourceと
	// source_idにより出所を必ず記録する"): it looks for an existing
	// CVE-less Vulnerability already registered under the same
	// (source, sourceID) pair, so repeated detection of the same
	// non-CVE issue confirms the existing record instead of creating a
	// duplicate. Returns (nil, nil), not an error, when none exists yet.
	FindByProvenanceSourceID(ctx context.Context, source, sourceID string) (*vulnerability.Vulnerability, error)
	// List returns every Vulnerability, for `riskforge vulnerability list`
	// and GET /api/v1/vulnerabilities (ADR 0011 flagged this as a gap to
	// fill when needed, rather than speculatively).
	List(ctx context.Context) ([]*vulnerability.Vulnerability, error)
}

// RawFindingRepository persists RawFindings that MatchRawFinding (ADR
// 0015-0018) held rather than acted on (ClassificationUnclassified,
// AGENTS.md §20A.2 case 3). It is intentionally write-and-list only: a
// held RawFinding is reviewed by a human, not programmatically updated by
// this package.
type RawFindingRepository interface {
	Save(ctx context.Context, rf *rawfinding.RawFinding) error
	FindByID(ctx context.Context, id rawfinding.ID) (*rawfinding.RawFinding, error)
	// List returns every held RawFinding, for a future review UI/CLI
	// command (not yet implemented -- ADR 0018 "対象外").
	List(ctx context.Context) ([]*rawfinding.RawFinding, error)
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
	// List returns every Finding, for `riskforge finding list` (AGENTS.md
	// §27).
	List(ctx context.Context) ([]*finding.Finding, error)
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
	// ListLatest returns the most recent PriorityDecision for every
	// Finding that has one, for `riskforge priority list` (AGENTS.md
	// §27).
	ListLatest(ctx context.Context) ([]*priority.Decision, error)
}

// RemediationPlanRepository persists and retrieves RemediationPlans.
type RemediationPlanRepository interface {
	Save(ctx context.Context, p *remediation.Plan) error
	FindByID(ctx context.Context, id remediation.ID) (*remediation.Plan, error)
	// List returns every RemediationPlan, for `riskforge remediation list`
	// (AGENTS.md §27).
	List(ctx context.Context) ([]*remediation.Plan, error)
}

// VerificationRepository persists and retrieves Verifications.
type VerificationRepository interface {
	Save(ctx context.Context, v *verification.Verification) error
	// List returns every Verification, for `riskforge verification list`
	// and GET /api/v1/verifications.
	List(ctx context.Context) ([]*verification.Verification, error)
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
	// List returns every Exception, for `riskforge exception list`
	// (AGENTS.md §27).
	List(ctx context.Context) ([]*exception.Exception, error)
}

// AuditRepository appends audit.Entry records. There is deliberately no
// update or delete method (AGENTS.md §30, mirroring §22/§47.10 for
// Evidence): an audit trail that could be edited after the fact would
// defeat its purpose.
type AuditRepository interface {
	Save(ctx context.Context, e *audit.Entry) error
}

// PrincipalRepository persists and retrieves Principals (ADR 0012).
type PrincipalRepository interface {
	Save(ctx context.Context, p *authn.Principal) error
	FindByID(ctx context.Context, id authn.PrincipalID) (*authn.Principal, error)
	// FindByName is CreateAPIToken's find-or-create key: reissuing a
	// token for a principal name that already exists attaches the new
	// token to the existing Principal instead of creating a duplicate.
	FindByName(ctx context.Context, name string) (*authn.Principal, error)
}

// APITokenRepository persists and retrieves APITokens (ADR 0012).
type APITokenRepository interface {
	Save(ctx context.Context, t *authn.APIToken) error
	FindByID(ctx context.Context, id authn.TokenID) (*authn.APIToken, error)
	// FindByTokenHash is AuthenticateToken's lookup key: a presented
	// bearer token is hashed and looked up by that hash, never by ID.
	FindByTokenHash(ctx context.Context, tokenHash string) (*authn.APIToken, error)
	// List returns every APIToken, for `riskforge token list`.
	List(ctx context.Context) ([]*authn.APIToken, error)
}

// RemediationExecutor performs the actual, infrastructure-level change a
// RemediationPlan describes (the validated, structured,
// allowlist-checked command execution required by AGENTS.md §31, §32).
// No implementation exists yet — providing one is Infrastructure's job in
// a later phase; ExecuteRemediation only defines the seam.
type RemediationExecutor interface {
	Execute(ctx context.Context, plan *remediation.Plan, target remediation.DryRunInput) error
}
