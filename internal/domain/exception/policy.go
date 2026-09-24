package exception

import (
	"fmt"
	"time"
)

// Policy is the exception_policy named in AGENTS.md §23: an
// organizational limit on how long an Exception may run before it must
// come up for re-approval, enforcing "永久的な例外をデフォルトにしない"
// (§18) beyond New's bare requirement that ExpiresAt be set at all.
//
// The zero value (MaxDuration: 0) allows any duration; callers that want
// the "never permanent" rule enforced must configure a MaxDuration.
type Policy struct {
	MaxDuration time.Duration
}

// Validate reports whether e's requested lifetime (ExpiresAt - CreatedAt)
// fits within p's MaxDuration.
func (p Policy) Validate(e *Exception) error {
	if p.MaxDuration <= 0 {
		return nil
	}
	if requested := e.ExpiresAt.Sub(e.CreatedAt); requested > p.MaxDuration {
		return fmt.Errorf("exception: requested duration %s exceeds policy maximum %s", requested, p.MaxDuration)
	}
	return nil
}
