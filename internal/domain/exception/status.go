package exception

// Status is the Exception's position in its approval lifecycle
// (AGENTS.md §18).
type Status string

const (
	StatusRequested Status = "requested"
	StatusApproved  Status = "approved"
	StatusRejected  Status = "rejected"
	StatusExpired   Status = "expired"
	StatusRevoked   Status = "revoked"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusRequested, StatusApproved, StatusRejected, StatusExpired, StatusRevoked:
		return true
	}
	return false
}

// validTransitions encodes the Exception lifecycle (AGENTS.md §18). Only
// an Approved exception can Expire or be Revoked: a Rejected request
// never took effect, so it has nothing to expire or revoke.
var validTransitions = map[Status]map[Status]bool{
	StatusRequested: {
		StatusApproved: true,
		StatusRejected: true,
	},
	StatusApproved: {
		StatusExpired: true,
		StatusRevoked: true,
	},
	StatusRejected: {},
	StatusExpired:  {},
	StatusRevoked:  {},
}
