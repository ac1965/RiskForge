package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies an Evidence record.
type ID string

// NewID returns a new random Evidence ID.
func NewID() ID {
	return ID(id.New())
}

// Evidence is a first-class, tamper-evident record (AGENTS.md §17). It has
// no setters: once created, every field is final. A correction is a new
// Evidence record, never a mutation of an existing one.
type Evidence struct {
	ID          ID
	Type        string
	Source      string
	CollectedAt time.Time
	AssetID     asset.ID
	FindingID   finding.ID // optional: may be collected before correlation to a Finding
	ContentHash string
	Location    string
}

// Params holds the fields needed to create a new Evidence record.
type Params struct {
	Type        string
	Source      string
	CollectedAt time.Time
	AssetID     asset.ID
	FindingID   finding.ID
	ContentHash string
	Location    string
}

// New creates an Evidence record from p, validating required fields.
// FindingID is the only optional field: evidence (e.g. a raw scan result)
// may be collected before it is correlated to a specific Finding.
func New(p Params) (*Evidence, error) {
	if strings.TrimSpace(p.Type) == "" {
		return nil, fmt.Errorf("evidence: type is required")
	}
	if strings.TrimSpace(p.Source) == "" {
		return nil, fmt.Errorf("evidence: source is required")
	}
	if p.CollectedAt.IsZero() {
		return nil, fmt.Errorf("evidence: collected at is required")
	}
	if strings.TrimSpace(string(p.AssetID)) == "" {
		return nil, fmt.Errorf("evidence: asset id is required")
	}
	if strings.TrimSpace(p.ContentHash) == "" {
		return nil, fmt.Errorf("evidence: content hash is required")
	}
	if strings.TrimSpace(p.Location) == "" {
		return nil, fmt.Errorf("evidence: location is required")
	}

	return &Evidence{
		ID:          NewID(),
		Type:        p.Type,
		Source:      p.Source,
		CollectedAt: p.CollectedAt,
		AssetID:     p.AssetID,
		FindingID:   p.FindingID,
		ContentHash: p.ContentHash,
		Location:    p.Location,
	}, nil
}
