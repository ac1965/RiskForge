package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/remediation"
)

func testRemediationParams(findingID finding.ID) remediation.Params {
	return remediation.Params{
		FindingID:   findingID,
		ActionType:  remediation.ActionPatch,
		Description: "Apply vendor patch",
		ProposedBy:  "alice",
		Rollback:    remediation.Rollback{Capable: true, Plan: "Downgrade package"},
	}
}

func TestRemediationLifecycleSuccess(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)

	plan, err := svc.CreateRemediationPlan(ctx, testRemediationParams(findingID))
	if err != nil {
		t.Fatalf("CreateRemediationPlan() unexpected error: %v", err)
	}

	if _, err := svc.ExecuteRemediation(ctx, plan.ID, "worker", "scheduled run", time.Now(), succeedingExecutor{}); err == nil {
		t.Error("ExecuteRemediation() before approval: want error, got nil")
	}

	if _, err := svc.ApproveRemediationPlan(ctx, plan.ID, "bob", "reviewed and safe"); err != nil {
		t.Fatalf("ApproveRemediationPlan() unexpected error: %v", err)
	}

	executed, err := svc.ExecuteRemediation(ctx, plan.ID, "worker", "scheduled run", time.Now(), succeedingExecutor{})
	if err != nil {
		t.Fatalf("ExecuteRemediation() unexpected error: %v", err)
	}
	if executed.Status != remediation.StatusCompleted {
		t.Errorf("Status = %s, want %s", executed.Status, remediation.StatusCompleted)
	}

	f, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if f.Status != finding.StatusRemediated {
		t.Errorf("finding status = %s, want %s", f.Status, finding.StatusRemediated)
	}

	var sawApproval, sawExecution bool
	for _, e := range repos.audit.saved {
		switch e.Action {
		case audit.ActionRemediationApproval:
			sawApproval = true
		case audit.ActionRemediationExecution:
			sawExecution = true
		}
	}
	if !sawApproval {
		t.Error("no remediation_approval audit entry recorded")
	}
	if !sawExecution {
		t.Error("no remediation_execution audit entry recorded")
	}
}

// TestRemediationExecutionFailureDoesNotAdvanceFinding confirms that a
// failed execution leaves the plan Failed and the Finding untouched — a
// failure must never look like a successful remediation.
func TestRemediationExecutionFailureDoesNotAdvanceFinding(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)

	plan, err := svc.CreateRemediationPlan(ctx, testRemediationParams(findingID))
	if err != nil {
		t.Fatalf("CreateRemediationPlan() unexpected error: %v", err)
	}
	if _, err := svc.ApproveRemediationPlan(ctx, plan.ID, "bob", "reviewed"); err != nil {
		t.Fatalf("ApproveRemediationPlan() unexpected error: %v", err)
	}

	executed, err := svc.ExecuteRemediation(ctx, plan.ID, "worker", "scheduled run", time.Now(), failingExecutor{})
	if err != nil {
		t.Fatalf("ExecuteRemediation() unexpected error: %v", err)
	}
	if executed.Status != remediation.StatusFailed {
		t.Errorf("Status = %s, want %s", executed.Status, remediation.StatusFailed)
	}

	f, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if f.Status != finding.StatusOpen {
		t.Errorf("finding status = %s, want unchanged %s", f.Status, finding.StatusOpen)
	}
}

func TestPreviewRemediation(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)

	plan, err := svc.CreateRemediationPlan(ctx, testRemediationParams(findingID))
	if err != nil {
		t.Fatalf("CreateRemediationPlan() unexpected error: %v", err)
	}

	report, err := svc.PreviewRemediation(ctx, plan.ID, "openssl 3.0.13 -> 3.0.14")
	if err != nil {
		t.Fatalf("PreviewRemediation() unexpected error: %v", err)
	}
	if report.FindingID != findingID {
		t.Errorf("report FindingID = %s, want %s", report.FindingID, findingID)
	}

	// A preview must never change the plan's status.
	stored, err := repos.remediationPlans.FindByID(ctx, plan.ID)
	if err != nil {
		t.Fatalf("find plan: %v", err)
	}
	if stored.Status != remediation.StatusProposed {
		t.Errorf("plan status after preview = %s, want unchanged %s", stored.Status, remediation.StatusProposed)
	}
}
