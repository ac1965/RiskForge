package risk

// Level is a coarse categorization of a risk Score, used for display and
// filtering. It is a distinct type from priority.Level (AGENTS.md §44
// Invariant 2: Risk != Priority) even though the value sets look similar.
type Level string

const (
	LevelCritical Level = "critical"
	LevelHigh     Level = "high"
	LevelMedium   Level = "medium"
	LevelLow      Level = "low"
	LevelUnknown  Level = "unknown"
)

// Valid reports whether l is one of the defined risk levels.
func (l Level) Valid() bool {
	switch l {
	case LevelCritical, LevelHigh, LevelMedium, LevelLow, LevelUnknown:
		return true
	}
	return false
}
