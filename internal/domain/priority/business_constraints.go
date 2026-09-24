package priority

import "time"

// TimeWindow is a half-open time range [Start, End).
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// Contains reports whether t falls within the window.
func (w TimeWindow) Contains(t time.Time) bool {
	return !t.Before(w.Start) && t.Before(w.End)
}

// BusinessConstraints captures operational constraints that affect
// remediation ordering (AGENTS.md §12) independent of technical risk: a
// change freeze, an upcoming maintenance window, or an external
// compliance deadline.
type BusinessConstraints struct {
	ChangeFreeze       bool
	MaintenanceWindow  *TimeWindow
	ComplianceDeadline *time.Time
}
