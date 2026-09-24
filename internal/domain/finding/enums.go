package finding

// Status is the Finding's position in its detection → resolution lifecycle
// (AGENTS.md §16).
type Status string

const (
	StatusOpen          Status = "open"
	StatusMitigated     Status = "mitigated"
	StatusRemediated    Status = "remediated"
	StatusVerified      Status = "verified"
	StatusReopened      Status = "reopened"
	StatusAccepted      Status = "accepted"
	StatusFalsePositive Status = "false_positive"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusMitigated, StatusRemediated, StatusVerified,
		StatusReopened, StatusAccepted, StatusFalsePositive:
		return true
	}
	return false
}

// Confidence expresses how certain the detection is (AGENTS.md §21). A
// version-estimate match alone must not produce a Confirmed finding.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceHigh      Confidence = "high"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceLow       Confidence = "low"
	ConfidenceUnknown   Confidence = "unknown"
)

// Valid reports whether c is one of the defined confidence levels.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceConfirmed, ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceUnknown:
		return true
	}
	return false
}
