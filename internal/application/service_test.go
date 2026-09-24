package application

import (
	"testing"

	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/risk"
)

type testRepos struct {
	assets            *assetRepo
	software          *softwareRepo
	vulnerabilities   *vulnerabilityRepo
	findings          *findingRepo
	riskAssessments   *riskAssessmentRepo
	priorityDecisions *priorityDecisionRepo
	remediationPlans  *remediationPlanRepo
	verifications     *verificationRepo
	evidence          *evidenceRepo
	exceptions        *exceptionRepo
	audit             *auditRepo
}

func newTestService(t *testing.T) (*Service, *testRepos) {
	t.Helper()

	repos := &testRepos{
		assets:            newAssetRepo(),
		software:          newSoftwareRepo(),
		vulnerabilities:   newVulnerabilityRepo(),
		findings:          newFindingRepo(),
		riskAssessments:   newRiskAssessmentRepo(),
		priorityDecisions: newPriorityDecisionRepo(),
		remediationPlans:  newRemediationPlanRepo(),
		verifications:     newVerificationRepo(),
		evidence:          newEvidenceRepo(),
		exceptions:        newExceptionRepo(),
		audit:             newAuditRepo(),
	}

	riskEngine, err := risk.NewEngine(
		risk.FromVulnerabilityProvider{},
		risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{},
		risk.FromAssetProvider{},
		risk.StaticBusinessImpactProvider{},
		risk.BaselinePolicy{},
	)
	if err != nil {
		t.Fatalf("risk.NewEngine() unexpected error: %v", err)
	}

	priorityEngine, err := priority.NewEngine(
		risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{},
		risk.FromAssetProvider{},
		priority.FromVulnerabilityRemediationProvider{},
		priority.StaticBusinessConstraintsProvider{},
		priority.BaselinePolicy{},
		priority.NewDefaultSLAPolicy(),
	)
	if err != nil {
		t.Fatalf("priority.NewEngine() unexpected error: %v", err)
	}

	svc, err := NewService(Service{
		Assets:            repos.assets,
		Software:          repos.software,
		Vulnerabilities:   repos.vulnerabilities,
		Findings:          repos.findings,
		RiskAssessments:   repos.riskAssessments,
		PriorityDecisions: repos.priorityDecisions,
		RemediationPlans:  repos.remediationPlans,
		Verifications:     repos.verifications,
		Evidence:          repos.evidence,
		Exceptions:        repos.exceptions,
		Audit:             repos.audit,
		RiskEngine:        riskEngine,
		PriorityEngine:    priorityEngine,
	})
	if err != nil {
		t.Fatalf("NewService() unexpected error: %v", err)
	}

	return svc, repos
}

func TestNewServiceRequiresAllDependencies(t *testing.T) {
	_, repos := newTestService(t)

	riskEngine, _ := risk.NewEngine(
		risk.FromVulnerabilityProvider{}, risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{}, risk.FromAssetProvider{},
		risk.StaticBusinessImpactProvider{}, risk.BaselinePolicy{},
	)
	priorityEngine, _ := priority.NewEngine(
		risk.FromVulnerabilityProvider{}, risk.FromAssetProvider{}, risk.FromAssetProvider{},
		priority.FromVulnerabilityRemediationProvider{}, priority.StaticBusinessConstraintsProvider{},
		priority.BaselinePolicy{}, priority.NewDefaultSLAPolicy(),
	)

	full := Service{
		Assets: repos.assets, Software: repos.software, Vulnerabilities: repos.vulnerabilities,
		Findings: repos.findings, RiskAssessments: repos.riskAssessments, PriorityDecisions: repos.priorityDecisions,
		RemediationPlans: repos.remediationPlans, Verifications: repos.verifications, Evidence: repos.evidence,
		Exceptions: repos.exceptions, Audit: repos.audit, RiskEngine: riskEngine, PriorityEngine: priorityEngine,
	}

	missing := full
	missing.Audit = nil
	if _, err := NewService(missing); err == nil {
		t.Error("NewService() with nil Audit: want error, got nil")
	}

	missing = full
	missing.RiskEngine = nil
	if _, err := NewService(missing); err == nil {
		t.Error("NewService() with nil RiskEngine: want error, got nil")
	}
}
