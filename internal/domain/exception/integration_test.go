package exception

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

// TestFindingLifecycleWithException exercises the full loop described in
// AGENTS.md §18: an approved exception moves the Finding to Accepted, and
// its later expiry reopens the Finding — both transitions must be valid
// moves under finding.Finding's own state machine (Phase 1), not just
// under Exception's.
func TestFindingLifecycleWithException(t *testing.T) {
	f, err := finding.New(finding.Params{
		AssetID:         "asset-1",
		VulnerabilityID: "vuln-1",
		DetectionSource: "test-scanner",
		DetectedAt:      time.Now(),
		Confidence:      finding.ConfidenceMedium,
	})
	if err != nil {
		t.Fatalf("finding.New() unexpected error: %v", err)
	}

	p := validParams()
	p.FindingID = f.ID
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if err := e.Approve("bob"); err != nil {
		t.Fatalf("Approve() unexpected error: %v", err)
	}
	status, apply := e.ImpliedFindingStatus()
	if !apply {
		t.Fatal("ImpliedFindingStatus() apply = false after approval, want true")
	}
	if err := f.TransitionTo(status); err != nil {
		t.Fatalf("finding.TransitionTo(%s) unexpected error: %v", status, err)
	}
	if f.Status != finding.StatusAccepted {
		t.Fatalf("finding status = %s, want %s", f.Status, finding.StatusAccepted)
	}

	if err := e.Expire(); err != nil {
		t.Fatalf("Expire() unexpected error: %v", err)
	}
	status, apply = e.ImpliedFindingStatus()
	if !apply {
		t.Fatal("ImpliedFindingStatus() apply = false after expiry, want true")
	}
	if err := f.TransitionTo(status); err != nil {
		t.Fatalf("finding.TransitionTo(%s) unexpected error: %v", status, err)
	}
	if f.Status != finding.StatusReopened {
		t.Fatalf("finding status = %s, want %s", f.Status, finding.StatusReopened)
	}
}
