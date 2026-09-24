package exception

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies an Exception.
type ID string

// NewID returns a new random Exception ID.
func NewID() ID {
	return ID(id.New())
}

// ErrInvalidTransition is returned by the Exception lifecycle methods
// when the requested status change is not a valid move from the
// Exception's current status.
var ErrInvalidTransition = errors.New("exception: invalid status transition")

// Exception is a formally tracked risk acceptance or false-positive
// suppression for a Finding (AGENTS.md §18). It is never permanent by
// default: ExpiresAt is always required.
type Exception struct {
	ID                  ID
	FindingID           finding.ID
	Reason              string
	RequestedBy         string
	ApprovedBy          string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	CompensatingControl string
	Status              Status
}

// Params holds the fields needed to request a new Exception.
type Params struct {
	FindingID           finding.ID
	Reason              string
	RequestedBy         string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	CompensatingControl string
}

// New requests an Exception from p. Every new Exception starts in
// StatusRequested; use Approve or Reject to move it forward.
// CompensatingControl is optional — not every accepted risk has one, but
// when present it is recorded.
func New(p Params) (*Exception, error) {
	if strings.TrimSpace(string(p.FindingID)) == "" {
		return nil, fmt.Errorf("exception: finding id is required")
	}
	if strings.TrimSpace(p.Reason) == "" {
		return nil, fmt.Errorf("exception: reason is required")
	}
	if strings.TrimSpace(p.RequestedBy) == "" {
		return nil, fmt.Errorf("exception: requested by is required")
	}
	if p.CreatedAt.IsZero() {
		return nil, fmt.Errorf("exception: created at is required")
	}
	if p.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("exception: expires at is required (exceptions are never permanent by default)")
	}
	if !p.ExpiresAt.After(p.CreatedAt) {
		return nil, fmt.Errorf("exception: expires at (%s) must be after created at (%s)", p.ExpiresAt, p.CreatedAt)
	}

	return &Exception{
		ID:                  NewID(),
		FindingID:           p.FindingID,
		Reason:              p.Reason,
		RequestedBy:         p.RequestedBy,
		CreatedAt:           p.CreatedAt,
		ExpiresAt:           p.ExpiresAt,
		CompensatingControl: p.CompensatingControl,
		Status:              StatusRequested,
	}, nil
}

func (e *Exception) transitionTo(next Status) error {
	if !validTransitions[e.Status][next] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, e.Status, next)
	}
	e.Status = next
	return nil
}

// Approve grants the exception request.
func (e *Exception) Approve(by string) error {
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("exception: approver is required")
	}
	if err := e.transitionTo(StatusApproved); err != nil {
		return err
	}
	e.ApprovedBy = by
	return nil
}

// Reject denies the exception request. The underlying Finding never left
// its prior status, so rejecting implies no Finding transition (see
// ImpliedFindingStatus).
func (e *Exception) Reject() error {
	return e.transitionTo(StatusRejected)
}

// Revoke ends an approved exception before its natural expiry.
func (e *Exception) Revoke() error {
	return e.transitionTo(StatusRevoked)
}

// Expire marks an approved exception as having reached its ExpiresAt.
func (e *Exception) Expire() error {
	return e.transitionTo(StatusExpired)
}

// IsExpired reports whether at is past ExpiresAt, regardless of Status —
// useful for finding requested-but-never-decided or approved-but-not-yet-
// formally-expired exceptions that are due for re-evaluation (AGENTS.md
// §18).
func (e *Exception) IsExpired(at time.Time) bool {
	return at.After(e.ExpiresAt)
}

// IsActive reports whether the exception is currently in effect: approved
// and not yet past its expiry.
func (e *Exception) IsActive(at time.Time) bool {
	return e.Status == StatusApproved && !e.IsExpired(at)
}

// ImpliedFindingStatus returns the finding.Status this Exception's
// Status implies, and whether a transition should be applied at all.
// StatusRequested and StatusRejected imply no transition: a request that
// was never approved never moved the Finding away from its prior status.
func (e *Exception) ImpliedFindingStatus() (status finding.Status, apply bool) {
	switch e.Status {
	case StatusApproved:
		return finding.StatusAccepted, true
	case StatusExpired, StatusRevoked:
		return finding.StatusReopened, true
	default:
		return "", false
	}
}
