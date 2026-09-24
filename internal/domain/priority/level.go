package priority

// Level is a coarse categorization of a priority Rank. It is a distinct
// type from risk.Level (AGENTS.md §44 Invariant 2: Risk != Priority) even
// though the value sets look similar.
type Level string

const (
	LevelCritical Level = "critical"
	LevelHigh     Level = "high"
	LevelMedium   Level = "medium"
	LevelLow      Level = "low"
)

// Valid reports whether l is one of the defined priority levels.
func (l Level) Valid() bool {
	switch l {
	case LevelCritical, LevelHigh, LevelMedium, LevelLow:
		return true
	}
	return false
}
