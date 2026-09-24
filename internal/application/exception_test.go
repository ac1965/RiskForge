package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func testExceptionParams(findingID finding.ID, createdAt time.Time) exception.Params {
	return exception.Params{
		FindingID:   findingID,
		Reason:      "Confirmed false positive after manual review",
		RequestedBy: "alice",
		CreatedAt:   createdAt,
		ExpiresAt:   createdAt.Add(90 * 24 * time.Hour),
	}
}

func TestExceptionLifecycleApprovalAndExpiry(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)
	createdAt := time.Now()

	e, err := svc.RequestException(ctx, testExceptionParams(findingID, createdAt), exception.Policy{})
	if err != nil {
		t.Fatalf("RequestException() unexpected error: %v", err)
	}

	var sawCreation bool
	for _, entry := range repos.audit.saved {
		if entry.Action == audit.ActionExceptionCreation && entry.SubjectID == string(findingID) {
			sawCreation = true
		}
	}
	if !sawCreation {
		t.Error("RequestException() did not record an exception_creation audit entry")
	}

	approved, err := svc.ApproveException(ctx, e.ID, "bob", "acceptable residual risk")
	if err != nil {
		t.Fatalf("ApproveException() unexpected error: %v", err)
	}
	if approved.Status != exception.StatusApproved {
		t.Errorf("Status = %s, want %s", approved.Status, exception.StatusApproved)
	}

	f, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if f.Status != finding.StatusAccepted {
		t.Errorf("finding status = %s, want %s", f.Status, finding.StatusAccepted)
	}

	expired, err := svc.ExpireException(ctx, e.ID, "reached expiry date")
	if err != nil {
		t.Fatalf("ExpireException() unexpected error: %v", err)
	}
	if expired.Status != exception.StatusExpired {
		t.Errorf("Status = %s, want %s", expired.Status, exception.StatusExpired)
	}

	f, err = repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if f.Status != finding.StatusReopened {
		t.Errorf("finding status = %s, want %s", f.Status, finding.StatusReopened)
	}

	var sawApproval, sawExpiration bool
	for _, entry := range repos.audit.saved {
		switch entry.Action {
		case audit.ActionExceptionApproval:
			sawApproval = true
		case audit.ActionExceptionExpiration:
			sawExpiration = true
		}
	}
	if !sawApproval {
		t.Error("no exception_approval audit entry recorded")
	}
	if !sawExpiration {
		t.Error("no exception_expiration audit entry recorded")
	}
}

// TestRequestExceptionRejectsPolicyViolation confirms AGENTS.md §18's "no
// permanent exceptions by default": a request exceeding the organization's
// configured MaxDuration must be rejected before it is persisted.
func TestRequestExceptionRejectsPolicyViolation(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)
	createdAt := time.Now()

	strict := exception.Policy{MaxDuration: 30 * 24 * time.Hour}
	if _, err := svc.RequestException(ctx, testExceptionParams(findingID, createdAt), strict); err == nil {
		t.Error("RequestException() exceeding policy max duration: want error, got nil")
	}
	if len(repos.exceptions.byID) != 0 {
		t.Error("a policy-violating exception request was persisted")
	}
}

func TestRejectExceptionLeavesFindingUnchanged(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	findingID := seedFinding(t, svc, repos)

	e, err := svc.RequestException(ctx, testExceptionParams(findingID, time.Now()), exception.Policy{})
	if err != nil {
		t.Fatalf("RequestException() unexpected error: %v", err)
	}

	beforeStatus, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}

	rejected, err := svc.RejectException(ctx, e.ID)
	if err != nil {
		t.Fatalf("RejectException() unexpected error: %v", err)
	}
	if rejected.Status != exception.StatusRejected {
		t.Errorf("Status = %s, want %s", rejected.Status, exception.StatusRejected)
	}

	after, err := repos.findings.FindByID(ctx, findingID)
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if after.Status != beforeStatus.Status {
		t.Errorf("finding status changed to %s after rejection, want unchanged %s", after.Status, beforeStatus.Status)
	}
}
