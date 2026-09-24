package priority

import (
	"fmt"
	"time"
)

// SLAPolicy computes a remediation deadline for a Finding at a given
// priority Level. AGENTS.md §43 gives example durations (Critical: 7
// days, High: 30, Medium: 90, Low: 180) but requires them to be
// organizational policy, not fixed values baked into code — so this is an
// interface, and DefaultSLAPolicy takes its durations as configuration.
type SLAPolicy interface {
	Deadline(level Level, detectedAt time.Time) (time.Time, error)
}

// DefaultSLAPolicy computes a deadline as detectedAt plus a
// per-Level duration. It is a reference implementation, not a hardcoded
// organizational policy: callers supply their own Durations.
type DefaultSLAPolicy struct {
	Durations map[Level]time.Duration
}

// NewDefaultSLAPolicy returns a DefaultSLAPolicy seeded with the example
// durations from AGENTS.md §43 (Critical: 7d, High: 30d, Medium: 90d,
// Low: 180d). Callers needing different durations should build a
// DefaultSLAPolicy directly instead of relying on these values.
func NewDefaultSLAPolicy() DefaultSLAPolicy {
	return DefaultSLAPolicy{
		Durations: map[Level]time.Duration{
			LevelCritical: 7 * 24 * time.Hour,
			LevelHigh:     30 * 24 * time.Hour,
			LevelMedium:   90 * 24 * time.Hour,
			LevelLow:      180 * 24 * time.Hour,
		},
	}
}

// Deadline returns detectedAt plus the configured duration for level.
func (p DefaultSLAPolicy) Deadline(level Level, detectedAt time.Time) (time.Time, error) {
	d, ok := p.Durations[level]
	if !ok {
		return time.Time{}, fmt.Errorf("priority: no SLA duration configured for level %q", level)
	}
	return detectedAt.Add(d), nil
}
