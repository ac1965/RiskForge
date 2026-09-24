package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/exception"
)

// RequestException is not one of AGENTS.md §26's named examples, but
// Exception (AGENTS.md §18, Phase 4) needs an entry point the same way
// remediation does. orgPolicy caps how long the requested exception may
// run (AGENTS.md §18: "永久的な例外をデフォルトにしない"); a request that
// exceeds it is rejected before being persisted. It records an
// exception_creation audit.Entry (AGENTS.md §30).
func (s *Service) RequestException(ctx context.Context, p exception.Params, orgPolicy exception.Policy) (*exception.Exception, error) {
	f, err := s.Findings.FindByID(ctx, p.FindingID)
	if err != nil {
		return nil, fmt.Errorf("application: find finding %s: %w", p.FindingID, err)
	}
	if f == nil {
		return nil, fmt.Errorf("application: finding %s not found", p.FindingID)
	}

	e, err := exception.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: request exception: %w", err)
	}
	if err := orgPolicy.Validate(e); err != nil {
		return nil, fmt.Errorf("application: exception request violates policy: %w", err)
	}
	if err := s.Exceptions.Save(ctx, e); err != nil {
		return nil, fmt.Errorf("application: save exception %s: %w", e.ID, err)
	}

	entry, err := audit.New(audit.Params{
		Action:      audit.ActionExceptionCreation,
		Who:         p.RequestedBy,
		SubjectType: "finding",
		SubjectID:   string(p.FindingID),
		What:        fmt.Sprintf("Requested exception %s, expiring %s", e.ID, e.ExpiresAt.Format(time.RFC3339)),
		Why:         p.Reason,
		Before:      "",
		After:       toJSON(e),
		OccurredAt:  p.CreatedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return e, nil
}

// ApproveException grants an exception request, moves its Finding to
// StatusAccepted (AGENTS.md §18), and records an exception_approval
// audit.Entry.
func (s *Service) ApproveException(ctx context.Context, exceptionID exception.ID, approvedBy, reason string) (*exception.Exception, error) {
	e, err := s.Exceptions.FindByID(ctx, exceptionID)
	if err != nil {
		return nil, fmt.Errorf("application: find exception %s: %w", exceptionID, err)
	}
	if e == nil {
		return nil, fmt.Errorf("application: exception %s not found", exceptionID)
	}

	before := toJSON(e)
	if err := e.Approve(approvedBy); err != nil {
		return nil, fmt.Errorf("application: approve exception %s: %w", exceptionID, err)
	}
	if err := s.Exceptions.Save(ctx, e); err != nil {
		return nil, fmt.Errorf("application: save exception %s: %w", exceptionID, err)
	}

	status, apply := e.ImpliedFindingStatus()
	if err := s.applyFindingStatus(ctx, e.FindingID, status, apply); err != nil {
		return nil, err
	}

	entry, err := audit.New(audit.Params{
		Action:      audit.ActionExceptionApproval,
		Who:         approvedBy,
		SubjectType: "finding",
		SubjectID:   string(e.FindingID),
		What:        fmt.Sprintf("Approved exception %s", exceptionID),
		Why:         reason,
		Before:      before,
		After:       toJSON(e),
		OccurredAt:  time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return e, nil
}

// RejectException denies an exception request. It is not audited: a
// rejected request never moved its Finding (exception.Exception.
// ImpliedFindingStatus returns apply=false for it), and
// exception_approval/exception_expiration are the only exception-related
// actions AGENTS.md §30 names (see docs/adr/0008-application-layer.md).
func (s *Service) RejectException(ctx context.Context, exceptionID exception.ID) (*exception.Exception, error) {
	e, err := s.Exceptions.FindByID(ctx, exceptionID)
	if err != nil {
		return nil, fmt.Errorf("application: find exception %s: %w", exceptionID, err)
	}
	if e == nil {
		return nil, fmt.Errorf("application: exception %s not found", exceptionID)
	}

	if err := e.Reject(); err != nil {
		return nil, fmt.Errorf("application: reject exception %s: %w", exceptionID, err)
	}
	if err := s.Exceptions.Save(ctx, e); err != nil {
		return nil, fmt.Errorf("application: save exception %s: %w", exceptionID, err)
	}
	return e, nil
}

// ExpireException marks an approved exception as expired, reopens its
// Finding for re-evaluation (AGENTS.md §18), and records an
// exception_expiration audit.Entry.
func (s *Service) ExpireException(ctx context.Context, exceptionID exception.ID, reason string) (*exception.Exception, error) {
	e, err := s.Exceptions.FindByID(ctx, exceptionID)
	if err != nil {
		return nil, fmt.Errorf("application: find exception %s: %w", exceptionID, err)
	}
	if e == nil {
		return nil, fmt.Errorf("application: exception %s not found", exceptionID)
	}

	before := toJSON(e)
	if err := e.Expire(); err != nil {
		return nil, fmt.Errorf("application: expire exception %s: %w", exceptionID, err)
	}
	if err := s.Exceptions.Save(ctx, e); err != nil {
		return nil, fmt.Errorf("application: save exception %s: %w", exceptionID, err)
	}

	status, apply := e.ImpliedFindingStatus()
	if err := s.applyFindingStatus(ctx, e.FindingID, status, apply); err != nil {
		return nil, err
	}

	entry, err := audit.New(audit.Params{
		Action:      audit.ActionExceptionExpiration,
		Who:         "system",
		SubjectType: "finding",
		SubjectID:   string(e.FindingID),
		What:        fmt.Sprintf("Exception %s expired", exceptionID),
		Why:         reason,
		Before:      before,
		After:       toJSON(e),
		OccurredAt:  time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return e, nil
}

// RevokeException ends an approved exception before its natural expiry
// and reopens its Finding. It is not audited: exception revocation is not
// in AGENTS.md §30's list (see docs/adr/0008-application-layer.md).
func (s *Service) RevokeException(ctx context.Context, exceptionID exception.ID) (*exception.Exception, error) {
	e, err := s.Exceptions.FindByID(ctx, exceptionID)
	if err != nil {
		return nil, fmt.Errorf("application: find exception %s: %w", exceptionID, err)
	}
	if e == nil {
		return nil, fmt.Errorf("application: exception %s not found", exceptionID)
	}

	if err := e.Revoke(); err != nil {
		return nil, fmt.Errorf("application: revoke exception %s: %w", exceptionID, err)
	}
	if err := s.Exceptions.Save(ctx, e); err != nil {
		return nil, fmt.Errorf("application: save exception %s: %w", exceptionID, err)
	}

	status, apply := e.ImpliedFindingStatus()
	if err := s.applyFindingStatus(ctx, e.FindingID, status, apply); err != nil {
		return nil, err
	}

	return e, nil
}
