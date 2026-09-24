package remediation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies a RemediationPlan.
type ID string

// NewID returns a new random RemediationPlan ID.
func NewID() ID {
	return ID(id.New())
}

// ErrInvalidTransition is returned by the Plan lifecycle methods when the
// requested status change is not a valid move from the Plan's current
// status.
var ErrInvalidTransition = errors.New("remediation: invalid status transition")

// Plan is a proposed, approved, and executed remediation for a Finding
// (AGENTS.md §14). It is a distinct entity from Verification (AGENTS.md
// §44 Invariant 3): a Plan reaching StatusCompleted means the change was
// made, not that it was confirmed effective.
type Plan struct {
	ID          ID
	FindingID   finding.ID
	ActionType  ActionType
	Description string
	ProposedBy  string
	ApprovedBy  string
	ScheduledAt time.Time
	ExecutedAt  time.Time
	Status      Status
	Rollback    Rollback
}

// Params holds the fields needed to propose a new Plan.
type Params struct {
	FindingID   finding.ID
	ActionType  ActionType
	Description string
	ProposedBy  string
	Rollback    Rollback
}

// New proposes a Plan from p. Every new Plan starts in StatusProposed and
// carries no approver yet; use Approve to move it forward.
func New(p Params) (*Plan, error) {
	if strings.TrimSpace(string(p.FindingID)) == "" {
		return nil, fmt.Errorf("remediation: finding id is required")
	}
	if !p.ActionType.Valid() {
		return nil, fmt.Errorf("remediation: invalid action type %q", p.ActionType)
	}
	if strings.TrimSpace(p.Description) == "" {
		return nil, fmt.Errorf("remediation: description is required")
	}
	if strings.TrimSpace(p.ProposedBy) == "" {
		return nil, fmt.Errorf("remediation: proposed by is required")
	}
	if err := p.Rollback.Validate(); err != nil {
		return nil, err
	}

	return &Plan{
		ID:          NewID(),
		FindingID:   p.FindingID,
		ActionType:  p.ActionType,
		Description: p.Description,
		ProposedBy:  p.ProposedBy,
		Status:      StatusProposed,
		Rollback:    p.Rollback,
	}, nil
}

func (p *Plan) transitionTo(next Status) error {
	if !validTransitions[p.Status][next] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, p.Status, next)
	}
	p.Status = next
	return nil
}

// Approve records approval of the plan by an identified approver
// (AGENTS.md §31: approval and execution are separate operations).
func (p *Plan) Approve(by string) error {
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("remediation: approver is required")
	}
	if err := p.transitionTo(StatusApproved); err != nil {
		return err
	}
	p.ApprovedBy = by
	return nil
}

// Schedule records when an approved plan is scheduled to run.
func (p *Plan) Schedule(at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("remediation: scheduled at is required")
	}
	if err := p.transitionTo(StatusScheduled); err != nil {
		return err
	}
	p.ScheduledAt = at
	return nil
}

// Start marks execution as having begun at t. Only an Approved or
// Scheduled plan can start — a Proposed plan can never start directly,
// which is what keeps automatic remediation disabled by default
// (AGENTS.md §15, §47.7).
func (p *Plan) Start(t time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("remediation: executed at is required")
	}
	if err := p.transitionTo(StatusInProgress); err != nil {
		return err
	}
	p.ExecutedAt = t
	return nil
}

// Complete marks the plan's execution as successful. It does not verify
// the fix — that is Verification's job (AGENTS.md §16, §44 Invariant 3).
func (p *Plan) Complete() error {
	return p.transitionTo(StatusCompleted)
}

// Fail marks the plan's execution as unsuccessful.
func (p *Plan) Fail() error {
	return p.transitionTo(StatusFailed)
}

// RollBack reverts a completed or failed plan. It refuses to proceed when
// the plan has no rollback capability (AGENTS.md §34).
func (p *Plan) RollBack() error {
	if !p.Rollback.Capable {
		return fmt.Errorf("remediation: plan %s has no rollback capability: %s", p.ID, p.Rollback.Reason)
	}
	return p.transitionTo(StatusRolledBack)
}

// Cancel withdraws the plan before or during execution.
func (p *Plan) Cancel() error {
	return p.transitionTo(StatusCancelled)
}

// ImpliedFindingStatus returns the finding.Status that a Completed plan of
// this ActionType implies for its Finding. ActionAcceptRisk implies
// StatusAccepted, never StatusRemediated (AGENTS.md §13: accept_risk is
// never automatic remediation success). Every other action type implies
// StatusRemediated, which — per finding.Finding's own transition rules —
// still requires a separate Verification before becoming StatusVerified
// (AGENTS.md §16).
//
// Callers are expected to only apply this once Status is StatusCompleted;
// this method does not check that itself, since Plan does not hold a
// reference to the Finding it would mutate (aggregates stay independent).
func (p *Plan) ImpliedFindingStatus() finding.Status {
	if p.ActionType == ActionAcceptRisk {
		return finding.StatusAccepted
	}
	return finding.StatusRemediated
}
