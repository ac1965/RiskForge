package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies an audit Entry.
type ID string

// NewID returns a new random Entry ID.
func NewID() ID {
	return ID(id.New())
}

// Entry is an immutable record of a significant operation (AGENTS.md
// §30), tracking who did what, when, why, and the before/after state.
// SubjectType/SubjectID identify the affected record generically (e.g.
// SubjectType "finding", SubjectID a finding.ID) so this package does not
// need to import every other domain package.
type Entry struct {
	ID          ID
	Action      string
	Who         string
	SubjectType string
	SubjectID   string
	What        string
	Why         string
	Before      string
	After       string
	OccurredAt  time.Time
}

// Params holds the fields needed to record a new Entry. Before and After
// are pre-serialized snapshots (e.g. JSON) supplied by the caller — this
// package does not serialize domain entities itself (AGENTS.md §25) — and
// may be left empty where there is no prior state (e.g. a creation) or no
// resulting state (e.g. a rejection).
type Params struct {
	Action      string
	Who         string
	SubjectType string
	SubjectID   string
	What        string
	Why         string
	Before      string
	After       string
	OccurredAt  time.Time
}

// New records an Entry from p. Action, Who, SubjectType, SubjectID, What,
// Why, and OccurredAt are all required: an audit entry with no stated
// reason, or that cannot be tied to a specific record, is not useful as
// an audit trail (AGENTS.md §30).
func New(p Params) (*Entry, error) {
	if strings.TrimSpace(p.Action) == "" {
		return nil, fmt.Errorf("audit: action is required")
	}
	if strings.TrimSpace(p.Who) == "" {
		return nil, fmt.Errorf("audit: who is required")
	}
	if strings.TrimSpace(p.SubjectType) == "" {
		return nil, fmt.Errorf("audit: subject type is required")
	}
	if strings.TrimSpace(p.SubjectID) == "" {
		return nil, fmt.Errorf("audit: subject id is required")
	}
	if strings.TrimSpace(p.What) == "" {
		return nil, fmt.Errorf("audit: what is required")
	}
	if strings.TrimSpace(p.Why) == "" {
		return nil, fmt.Errorf("audit: why is required")
	}
	if p.OccurredAt.IsZero() {
		return nil, fmt.Errorf("audit: occurred at is required")
	}

	return &Entry{
		ID:          NewID(),
		Action:      p.Action,
		Who:         p.Who,
		SubjectType: p.SubjectType,
		SubjectID:   p.SubjectID,
		What:        p.What,
		Why:         p.Why,
		Before:      p.Before,
		After:       p.After,
		OccurredAt:  p.OccurredAt,
	}, nil
}
