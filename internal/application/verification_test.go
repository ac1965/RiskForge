package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/verification"
)

// remediateFinding drives a Finding through Approve+Execute so it reaches
// StatusRemediated, the precondition for a verification.ResultPass to
// imply StatusVerified.
func remediateFinding(t *testing.T, svc *Service, findingID finding.ID) {
	t.Helper()
	ctx := context.Background()

	plan, err := svc.CreateRemediationPlan(ctx, testRemediationParams(findingID))
	if err != nil {
		t.Fatalf("CreateRemediationPlan() unexpected error: %v", err)
	}
	if _, err := svc.ApproveRemediationPlan(ctx, plan.ID, "bob", "reviewed"); err != nil {
		t.Fatalf("ApproveRemediationPlan() unexpected error: %v", err)
	}
	if _, err := svc.ExecuteRemediation(ctx, plan.ID, "worker", "scheduled run", time.Now(), succeedingExecutor{}); err != nil {
		t.Fatalf("ExecuteRemediation() unexpected error: %v", err)
	}
}

func TestVerifyRemediationPass(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)
	remediateFinding(t, svc, findingID)

	f, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}

	ev, err := svc.RecordEvidence(ctx, evidence.Params{
		Type:        evidence.TypeVerificationResult,
		Source:      "riskforge-agent",
		CollectedAt: time.Now(),
		AssetID:     f.AssetID,
		FindingID:   findingID,
		ContentHash: evidence.ComputeContentHash([]byte("version check output")),
		Location:    "s3://evidence/verify-1.json",
	})
	if err != nil {
		t.Fatalf("RecordEvidence() unexpected error: %v", err)
	}

	v, err := svc.VerifyRemediation(ctx, verification.Params{
		FindingID:  findingID,
		Method:     verification.MethodVersionCheck,
		VerifiedAt: time.Now(),
		Result:     verification.ResultPass,
		EvidenceID: ev.ID,
	}, "carol", "post-patch rescan")
	if err != nil {
		t.Fatalf("VerifyRemediation() unexpected error: %v", err)
	}
	if v.Result != verification.ResultPass {
		t.Errorf("Result = %s, want %s", v.Result, verification.ResultPass)
	}

	updated, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if updated.Status != finding.StatusVerified {
		t.Errorf("finding status = %s, want %s", updated.Status, finding.StatusVerified)
	}
}

// TestVerifyRemediationInconclusiveLeavesFindingUnchanged is the AGENTS.md
// §20A.6.1 scenario: a check that could not run must never be treated as
// if the vulnerability were still present.
func TestVerifyRemediationInconclusiveLeavesFindingUnchanged(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)
	remediateFinding(t, svc, findingID)

	f, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	beforeStatus := f.Status

	ev, err := svc.RecordEvidence(ctx, evidence.Params{
		Type:        evidence.TypeVerificationResult,
		Source:      "riskforge-agent",
		CollectedAt: time.Now(),
		AssetID:     f.AssetID,
		FindingID:   findingID,
		ContentHash: evidence.ComputeContentHash([]byte("connection timed out")),
		Location:    "s3://evidence/verify-2.json",
	})
	if err != nil {
		t.Fatalf("RecordEvidence() unexpected error: %v", err)
	}

	if _, err := svc.VerifyRemediation(ctx, verification.Params{
		FindingID:  findingID,
		Method:     verification.MethodScannerRescan,
		VerifiedAt: time.Now(),
		Result:     verification.ResultInconclusive,
		EvidenceID: ev.ID,
	}, "carol", "asset unreachable during rescan"); err != nil {
		t.Fatalf("VerifyRemediation() unexpected error: %v", err)
	}

	updated, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if updated.Status != beforeStatus {
		t.Errorf("finding status changed to %s after inconclusive verification, want unchanged %s", updated.Status, beforeStatus)
	}
}
