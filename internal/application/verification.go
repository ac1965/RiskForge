package application

import (
	"context"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/verification"
)

// VerifyRemediation is the verify_remediation() Named API (AGENTS.md
// §26). It records the Verification, then applies whatever Finding status
// it implies (AGENTS.md §20A.6.1: Pass -> Verified, Fail -> Reopened,
// Inconclusive -> no change), and records a verification audit.Entry.
func (s *Service) VerifyRemediation(ctx context.Context, p verification.Params, performedBy, reason string) (*verification.Verification, error) {
	f, err := s.Findings.FindByID(ctx, p.FindingID)
	if err != nil {
		return nil, fmt.Errorf("application: find finding %s: %w", p.FindingID, err)
	}
	if f == nil {
		return nil, fmt.Errorf("application: finding %s not found", p.FindingID)
	}

	ev, err := s.Evidence.FindByID(ctx, p.EvidenceID)
	if err != nil {
		return nil, fmt.Errorf("application: find evidence %s: %w", p.EvidenceID, err)
	}
	if ev == nil {
		return nil, fmt.Errorf("application: evidence %s not found", p.EvidenceID)
	}

	v, err := verification.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: record verification: %w", err)
	}
	if err := s.Verifications.Save(ctx, v); err != nil {
		return nil, fmt.Errorf("application: save verification %s: %w", v.ID, err)
	}

	status, apply := v.ImpliedFindingStatus()
	if err := s.applyFindingStatus(ctx, p.FindingID, status, apply); err != nil {
		return nil, err
	}

	entry, err := audit.New(audit.Params{
		Action:      audit.ActionVerification,
		Who:         performedBy,
		SubjectType: "finding",
		SubjectID:   string(p.FindingID),
		What:        fmt.Sprintf("Verification %s for finding %s: %s (%s)", v.ID, p.FindingID, v.Result, v.Method),
		Why:         reason,
		Before:      toJSON(f),
		After:       toJSON(v),
		OccurredAt:  v.VerifiedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return v, nil
}
