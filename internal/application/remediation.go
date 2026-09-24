package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/remediation"
)

// CreateRemediationPlan is the create_remediation_plan() Named API
// (AGENTS.md §26). It is not audited: AGENTS.md §30's list of audited
// actions covers remediation_approval and remediation_execution, but not
// plan creation itself (see docs/adr/0008-application-layer.md).
func (s *Service) CreateRemediationPlan(ctx context.Context, p remediation.Params) (*remediation.Plan, error) {
	f, err := s.Findings.FindByID(ctx, p.FindingID)
	if err != nil {
		return nil, fmt.Errorf("application: find finding %s: %w", p.FindingID, err)
	}
	if f == nil {
		return nil, fmt.Errorf("application: finding %s not found", p.FindingID)
	}

	plan, err := remediation.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: create remediation plan: %w", err)
	}
	if err := s.RemediationPlans.Save(ctx, plan); err != nil {
		return nil, fmt.Errorf("application: save remediation plan %s: %w", plan.ID, err)
	}
	return plan, nil
}

// ApproveRemediationPlan is not one of AGENTS.md §26's named examples, but
// is required to use create_remediation_plan()/execute_remediation() at
// all: remediation.Plan's own state machine (AGENTS.md §15, §47.7)
// refuses to go straight from Proposed to InProgress. It records a
// remediation_approval audit.Entry (AGENTS.md §30).
func (s *Service) ApproveRemediationPlan(ctx context.Context, planID remediation.ID, approvedBy, reason string) (*remediation.Plan, error) {
	plan, err := s.RemediationPlans.FindByID(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("application: find remediation plan %s: %w", planID, err)
	}
	if plan == nil {
		return nil, fmt.Errorf("application: remediation plan %s not found", planID)
	}

	before := toJSON(plan)
	if err := plan.Approve(approvedBy); err != nil {
		return nil, fmt.Errorf("application: approve remediation plan %s: %w", planID, err)
	}
	if err := s.RemediationPlans.Save(ctx, plan); err != nil {
		return nil, fmt.Errorf("application: save remediation plan %s: %w", planID, err)
	}

	entry, err := audit.New(audit.Params{
		Action:      audit.ActionRemediationApproval,
		Who:         approvedBy,
		SubjectType: "remediation_plan",
		SubjectID:   string(planID),
		What:        fmt.Sprintf("Approved remediation plan %s", planID),
		Why:         reason,
		Before:      before,
		After:       toJSON(plan),
		OccurredAt:  time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return plan, nil
}

// PreviewRemediation runs a RemediationPlan's Dry Run (AGENTS.md §33)
// without making any change.
func (s *Service) PreviewRemediation(ctx context.Context, planID remediation.ID, target string) (*remediation.DryRunReport, error) {
	plan, err := s.RemediationPlans.FindByID(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("application: find remediation plan %s: %w", planID, err)
	}
	if plan == nil {
		return nil, fmt.Errorf("application: remediation plan %s not found", planID)
	}

	f, a, _, err := s.loadFindingContext(ctx, plan.FindingID)
	if err != nil {
		return nil, err
	}

	return plan.DryRun(remediation.DryRunInput{Finding: f, Asset: a}, target)
}

// ExecuteRemediation is the execute_remediation() Named API (AGENTS.md
// §26). It starts the plan, delegates the actual change to executor (the
// validated, structured, allowlisted command execution required by
// AGENTS.md §31, §32 — not implemented by this package), completes or
// fails the plan based on the outcome, applies the implied Finding status
// change (AGENTS.md §13: accept_risk never implies Remediated), and
// records a remediation_execution audit.Entry.
func (s *Service) ExecuteRemediation(
	ctx context.Context,
	planID remediation.ID,
	executedBy, reason string,
	at time.Time,
	executor RemediationExecutor,
) (*remediation.Plan, error) {
	plan, err := s.RemediationPlans.FindByID(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("application: find remediation plan %s: %w", planID, err)
	}
	if plan == nil {
		return nil, fmt.Errorf("application: remediation plan %s not found", planID)
	}

	f, a, _, err := s.loadFindingContext(ctx, plan.FindingID)
	if err != nil {
		return nil, err
	}

	before := toJSON(plan)
	if err := plan.Start(at); err != nil {
		return nil, fmt.Errorf("application: start remediation plan %s: %w", planID, err)
	}
	if err := s.RemediationPlans.Save(ctx, plan); err != nil {
		return nil, fmt.Errorf("application: save remediation plan %s: %w", planID, err)
	}

	execErr := executor.Execute(ctx, plan, remediation.DryRunInput{Finding: f, Asset: a})
	if execErr != nil {
		if err := plan.Fail(); err != nil {
			return nil, fmt.Errorf("application: fail remediation plan %s: %w", planID, err)
		}
	} else if err := plan.Complete(); err != nil {
		return nil, fmt.Errorf("application: complete remediation plan %s: %w", planID, err)
	}
	if err := s.RemediationPlans.Save(ctx, plan); err != nil {
		return nil, fmt.Errorf("application: save remediation plan %s: %w", planID, err)
	}

	if execErr == nil {
		if err := s.applyFindingStatus(ctx, plan.FindingID, plan.ImpliedFindingStatus(), true); err != nil {
			return nil, err
		}
	}

	what := fmt.Sprintf("Executed remediation plan %s", planID)
	if execErr != nil {
		what = fmt.Sprintf("Execution of remediation plan %s failed: %v", planID, execErr)
	}
	entry, err := audit.New(audit.Params{
		Action:      audit.ActionRemediationExecution,
		Who:         executedBy,
		SubjectType: "remediation_plan",
		SubjectID:   string(planID),
		What:        what,
		Why:         reason,
		Before:      before,
		After:       toJSON(plan),
		OccurredAt:  at,
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return plan, nil
}
