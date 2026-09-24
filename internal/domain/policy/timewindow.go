package policy

import "time"

// TimeWindow is a half-open time range [Start, End), used as
// AutoRemediationPolicy's maintenance window.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// Contains reports whether t falls within the window.
func (w TimeWindow) Contains(t time.Time) bool {
	return !t.Before(w.Start) && t.Before(w.End)
}
