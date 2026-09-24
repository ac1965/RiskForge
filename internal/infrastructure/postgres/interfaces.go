package postgres

import "github.com/ac1965/riskforge/internal/application"

// Compile-time checks that every repository in this package satisfies its
// corresponding application port (AGENTS.md §25 Layering).
var (
	_ application.AssetRepository            = (*AssetRepository)(nil)
	_ application.SoftwareRepository         = (*SoftwareRepository)(nil)
	_ application.VulnerabilityRepository    = (*VulnerabilityRepository)(nil)
	_ application.FindingRepository          = (*FindingRepository)(nil)
	_ application.RiskAssessmentRepository   = (*RiskAssessmentRepository)(nil)
	_ application.PriorityDecisionRepository = (*PriorityDecisionRepository)(nil)
	_ application.RemediationPlanRepository  = (*RemediationPlanRepository)(nil)
	_ application.VerificationRepository     = (*VerificationRepository)(nil)
	_ application.EvidenceRepository         = (*EvidenceRepository)(nil)
	_ application.ExceptionRepository        = (*ExceptionRepository)(nil)
	_ application.AuditRepository            = (*AuditRepository)(nil)
)
