package remediation

// Status is the RemediationPlan's position in its approval/execution
// lifecycle (AGENTS.md §14).
type Status string

const (
	StatusProposed   Status = "proposed"
	StatusApproved   Status = "approved"
	StatusScheduled  Status = "scheduled"
	StatusInProgress Status = "in_progress"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusRolledBack Status = "rolled_back"
	StatusCancelled  Status = "cancelled"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusProposed, StatusApproved, StatusScheduled, StatusInProgress,
		StatusCompleted, StatusFailed, StatusRolledBack, StatusCancelled:
		return true
	}
	return false
}

// validTransitions encodes the RemediationPlan lifecycle (AGENTS.md §14,
// §15). Notably, StatusProposed cannot move directly to StatusInProgress:
// a plan can only be executed after being approved, which is how
// automatic remediation being disabled by default (AGENTS.md §15, §47.7)
// is enforced at the domain level — nothing can skip the approval step.
var validTransitions = map[Status]map[Status]bool{
	StatusProposed: {
		StatusApproved:  true,
		StatusCancelled: true,
	},
	StatusApproved: {
		StatusScheduled:  true,
		StatusInProgress: true,
		StatusCancelled:  true,
	},
	StatusScheduled: {
		StatusInProgress: true,
		StatusCancelled:  true,
	},
	StatusInProgress: {
		StatusCompleted: true,
		StatusFailed:    true,
	},
	StatusCompleted: {
		StatusRolledBack: true,
	},
	StatusFailed: {
		StatusRolledBack: true,
		StatusCancelled:  true,
	},
	StatusRolledBack: {},
	StatusCancelled:  {},
}
