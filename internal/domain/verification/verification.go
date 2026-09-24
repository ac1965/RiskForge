package verification

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies a Verification.
type ID string

// NewID returns a new random Verification ID.
func NewID() ID {
	return ID(id.New())
}

// Verification is the record of confirming (or failing to confirm) that a
// Finding was actually fixed (AGENTS.md §16). It is a distinct entity
// from remediation.Plan (AGENTS.md §44 Invariant 3).
type Verification struct {
	ID         ID
	FindingID  finding.ID
	Method     Method
	VerifiedAt time.Time
	Result     Result
	EvidenceID evidence.ID
}

// Params holds the fields needed to record a new Verification.
type Params struct {
	FindingID  finding.ID
	Method     Method
	VerifiedAt time.Time
	Result     Result
	EvidenceID evidence.ID
}

// New records a Verification from p. EvidenceID is required: a
// verification result must always be backed by evidence of how it was
// obtained (AGENTS.md §16, §20A.6).
func New(p Params) (*Verification, error) {
	if strings.TrimSpace(string(p.FindingID)) == "" {
		return nil, fmt.Errorf("verification: finding id is required")
	}
	if !p.Method.Valid() {
		return nil, fmt.Errorf("verification: invalid method %q", p.Method)
	}
	if p.VerifiedAt.IsZero() {
		return nil, fmt.Errorf("verification: verified at is required")
	}
	if !p.Result.Valid() {
		return nil, fmt.Errorf("verification: invalid result %q", p.Result)
	}
	if strings.TrimSpace(string(p.EvidenceID)) == "" {
		return nil, fmt.Errorf("verification: evidence id is required")
	}

	return &Verification{
		ID:         NewID(),
		FindingID:  p.FindingID,
		Method:     p.Method,
		VerifiedAt: p.VerifiedAt,
		Result:     p.Result,
		EvidenceID: p.EvidenceID,
	}, nil
}

// ImpliedFindingStatus returns the finding.Status this Verification's
// Result implies, and whether a transition should be applied at all.
// ResultInconclusive implies no transition (AGENTS.md §20A.6.1): a check
// that could not run is never treated as if the vulnerability were still
// present.
func (v *Verification) ImpliedFindingStatus() (status finding.Status, apply bool) {
	switch v.Result {
	case ResultPass:
		return finding.StatusVerified, true
	case ResultFail:
		return finding.StatusReopened, true
	default:
		return "", false
	}
}
