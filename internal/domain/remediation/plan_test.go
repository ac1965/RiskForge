package remediation

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

func validParams() Params {
	return Params{
		FindingID:   finding.NewID(),
		ActionType:  ActionPatch,
		Description: "Apply vendor patch 1.2.3",
		ProposedBy:  "alice",
		Rollback:    Rollback{Capable: true, Plan: "Downgrade to 1.2.2"},
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing finding id", mutate: func(p *Params) { p.FindingID = "" }, wantErr: true},
		{name: "invalid action type", mutate: func(p *Params) { p.ActionType = "reboot" }, wantErr: true},
		{name: "missing description", mutate: func(p *Params) { p.Description = "" }, wantErr: true},
		{name: "missing proposed by", mutate: func(p *Params) { p.ProposedBy = "" }, wantErr: true},
		{
			name:    "rollback capable without plan",
			mutate:  func(p *Params) { p.Rollback = Rollback{Capable: true} },
			wantErr: true,
		},
		{
			name:    "rollback incapable without reason",
			mutate:  func(p *Params) { p.Rollback = Rollback{Capable: false} },
			wantErr: true,
		},
		{
			name:   "rollback incapable with reason",
			mutate: func(p *Params) { p.Rollback = Rollback{Capable: false, Reason: "no clean uninstall path"} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)

			plan, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if plan.ID == "" {
				t.Error("New() did not assign an ID")
			}
			if plan.Status != StatusProposed {
				t.Errorf("Status = %q, want %q", plan.Status, StatusProposed)
			}
		})
	}
}

func TestPlanLifecycleHappyPath(t *testing.T) {
	plan, err := New(validParams())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if err := plan.Approve("bob"); err != nil {
		t.Fatalf("Approve() unexpected error: %v", err)
	}
	if plan.ApprovedBy != "bob" {
		t.Errorf("ApprovedBy = %q, want %q", plan.ApprovedBy, "bob")
	}

	scheduledAt := time.Now().Add(24 * time.Hour)
	if err := plan.Schedule(scheduledAt); err != nil {
		t.Fatalf("Schedule() unexpected error: %v", err)
	}
	if !plan.ScheduledAt.Equal(scheduledAt) {
		t.Errorf("ScheduledAt = %s, want %s", plan.ScheduledAt, scheduledAt)
	}

	executedAt := scheduledAt.Add(time.Hour)
	if err := plan.Start(executedAt); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if !plan.ExecutedAt.Equal(executedAt) {
		t.Errorf("ExecutedAt = %s, want %s", plan.ExecutedAt, executedAt)
	}

	if err := plan.Complete(); err != nil {
		t.Fatalf("Complete() unexpected error: %v", err)
	}
	if plan.Status != StatusCompleted {
		t.Errorf("Status = %q, want %q", plan.Status, StatusCompleted)
	}

	if err := plan.RollBack(); err != nil {
		t.Fatalf("RollBack() unexpected error: %v", err)
	}
	if plan.Status != StatusRolledBack {
		t.Errorf("Status = %q, want %q", plan.Status, StatusRolledBack)
	}
}

// TestCannotStartWithoutApproval is the AGENTS.md §15 / §47.7 invariant:
// automatic remediation is disabled by default because a Plan can never
// reach StatusInProgress straight from StatusProposed.
func TestCannotStartWithoutApproval(t *testing.T) {
	plan, err := New(validParams())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if err := plan.Start(time.Now()); err == nil {
		t.Error("Start() from StatusProposed: want error, got nil")
	}
	if plan.Status != StatusProposed {
		t.Errorf("Status changed to %s after rejected Start(), want unchanged %s", plan.Status, StatusProposed)
	}
}

func TestRollBackRefusedWithoutCapability(t *testing.T) {
	p := validParams()
	p.Rollback = Rollback{Capable: false, Reason: "destructive uninstall"}
	plan, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if err := plan.Approve("bob"); err != nil {
		t.Fatalf("Approve() unexpected error: %v", err)
	}
	if err := plan.Start(time.Now()); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if err := plan.Complete(); err != nil {
		t.Fatalf("Complete() unexpected error: %v", err)
	}

	if err := plan.RollBack(); err == nil {
		t.Error("RollBack() on a plan with no rollback capability: want error, got nil")
	}
	if plan.Status != StatusCompleted {
		t.Errorf("Status changed to %s after rejected RollBack(), want unchanged %s", plan.Status, StatusCompleted)
	}
}

func TestImpliedFindingStatus(t *testing.T) {
	acceptRisk := validParams()
	acceptRisk.ActionType = ActionAcceptRisk
	acceptPlan, err := New(acceptRisk)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if got := acceptPlan.ImpliedFindingStatus(); got != finding.StatusAccepted {
		t.Errorf("ImpliedFindingStatus() for accept_risk = %s, want %s", got, finding.StatusAccepted)
	}

	patchPlan, err := New(validParams())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if got := patchPlan.ImpliedFindingStatus(); got != finding.StatusRemediated {
		t.Errorf("ImpliedFindingStatus() for patch = %s, want %s", got, finding.StatusRemediated)
	}
}
