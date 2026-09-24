package application

import (
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/risk"
)

// Service implements the Named Domain APIs (AGENTS.md §26). It holds
// every repository port and the pluggable engines those APIs delegate to;
// the CLI and API layers depend on Service, never on internal/domain
// directly (AGENTS.md §25 Layering).
type Service struct {
	Assets            AssetRepository
	Software          SoftwareRepository
	Vulnerabilities   VulnerabilityRepository
	Findings          FindingRepository
	RiskAssessments   RiskAssessmentRepository
	PriorityDecisions PriorityDecisionRepository
	RemediationPlans  RemediationPlanRepository
	Verifications     VerificationRepository
	Evidence          EvidenceRepository
	Exceptions        ExceptionRepository
	Audit             AuditRepository

	RiskEngine     *risk.Engine
	PriorityEngine *priority.Engine
}

// NewService validates that every dependency of deps is set and returns
// it as a ready-to-use Service.
func NewService(deps Service) (*Service, error) {
	switch {
	case deps.Assets == nil:
		return nil, fmt.Errorf("application: asset repository is required")
	case deps.Software == nil:
		return nil, fmt.Errorf("application: software repository is required")
	case deps.Vulnerabilities == nil:
		return nil, fmt.Errorf("application: vulnerability repository is required")
	case deps.Findings == nil:
		return nil, fmt.Errorf("application: finding repository is required")
	case deps.RiskAssessments == nil:
		return nil, fmt.Errorf("application: risk assessment repository is required")
	case deps.PriorityDecisions == nil:
		return nil, fmt.Errorf("application: priority decision repository is required")
	case deps.RemediationPlans == nil:
		return nil, fmt.Errorf("application: remediation plan repository is required")
	case deps.Verifications == nil:
		return nil, fmt.Errorf("application: verification repository is required")
	case deps.Evidence == nil:
		return nil, fmt.Errorf("application: evidence repository is required")
	case deps.Exceptions == nil:
		return nil, fmt.Errorf("application: exception repository is required")
	case deps.Audit == nil:
		return nil, fmt.Errorf("application: audit repository is required")
	case deps.RiskEngine == nil:
		return nil, fmt.Errorf("application: risk engine is required")
	case deps.PriorityEngine == nil:
		return nil, fmt.Errorf("application: priority engine is required")
	}

	return &deps, nil
}
