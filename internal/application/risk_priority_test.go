package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func seedFinding(t *testing.T, svc *Service, repos *testRepos) finding.ID {
	t.Helper()
	ctx := context.Background()
	assetID, vulnID := seedAssetAndVulnerability(t, svc, repos)

	f, err := svc.CorrelateFindings(ctx, finding.Params{
		AssetID:         assetID,
		VulnerabilityID: vulnID,
		DetectionSource: "test-scanner",
		DetectedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Confidence:      finding.ConfidenceConfirmed,
	})
	if err != nil {
		t.Fatalf("CorrelateFindings() unexpected error: %v", err)
	}
	return f.ID
}

func TestAssessRiskAndCalculatePriority(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)

	assessment, err := svc.AssessRisk(ctx, findingID)
	if err != nil {
		t.Fatalf("AssessRisk() unexpected error: %v", err)
	}
	if assessment.FindingID != findingID {
		t.Errorf("assessment FindingID = %s, want %s", assessment.FindingID, findingID)
	}

	foundRiskAudit := false
	for _, e := range repos.audit.saved {
		if e.Action == audit.ActionRiskChange && e.SubjectID == string(findingID) {
			foundRiskAudit = true
		}
	}
	if !foundRiskAudit {
		t.Error("AssessRisk() did not record a risk_change audit entry")
	}

	decision, err := svc.CalculatePriority(ctx, findingID)
	if err != nil {
		t.Fatalf("CalculatePriority() unexpected error: %v", err)
	}
	if decision.RiskAssessmentID != assessment.ID {
		t.Errorf("decision RiskAssessmentID = %s, want %s", decision.RiskAssessmentID, assessment.ID)
	}

	foundPriorityAudit := false
	for _, e := range repos.audit.saved {
		if e.Action == audit.ActionPriorityChange && e.SubjectID == string(findingID) {
			foundPriorityAudit = true
		}
	}
	if !foundPriorityAudit {
		t.Error("CalculatePriority() did not record a priority_change audit entry")
	}
}

// TestCalculatePriorityRequiresRiskAssessment enforces the pipeline order
// from AGENTS.md §24: Risk must be assessed before Priority is decided.
func TestCalculatePriorityRequiresRiskAssessment(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)

	if _, err := svc.CalculatePriority(ctx, findingID); err == nil {
		t.Error("CalculatePriority() without a prior risk assessment: want error, got nil")
	}
}
