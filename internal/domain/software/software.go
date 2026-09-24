package software

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies a SoftwareInstallation.
type ID string

// NewID returns a new random SoftwareInstallation ID.
func NewID() ID {
	return ID(id.New())
}

// Installation is a normalized record of a piece of software found on an
// asset (AGENTS.md §5). Vulnerability matching must not be driven by the
// raw Version string alone — CPE/PURL are the preferred identifiers when
// available.
type Installation struct {
	ID             ID
	AssetID        asset.ID
	Vendor         string
	Product        string
	Version        string
	Architecture   string
	PackageManager string
	InstallPath    string
	CPE            string
	PURL           string
	FirstSeen      time.Time
	LastSeen       time.Time
}

// Params holds the fields needed to create a new Installation.
type Params struct {
	AssetID        asset.ID
	Vendor         string
	Product        string
	Version        string
	Architecture   string
	PackageManager string
	InstallPath    string
	CPE            string
	PURL           string
	FirstSeen      time.Time
	LastSeen       time.Time
}

// New creates an Installation from p, validating required fields.
func New(p Params) (*Installation, error) {
	if strings.TrimSpace(string(p.AssetID)) == "" {
		return nil, fmt.Errorf("software: asset id is required")
	}
	if strings.TrimSpace(p.Vendor) == "" {
		return nil, fmt.Errorf("software: vendor is required")
	}
	if strings.TrimSpace(p.Product) == "" {
		return nil, fmt.Errorf("software: product is required")
	}
	if strings.TrimSpace(p.Version) == "" {
		return nil, fmt.Errorf("software: version is required")
	}
	if p.FirstSeen.IsZero() {
		return nil, fmt.Errorf("software: first seen is required")
	}
	if p.LastSeen.IsZero() {
		p.LastSeen = p.FirstSeen
	}
	if p.LastSeen.Before(p.FirstSeen) {
		return nil, fmt.Errorf("software: last seen (%s) precedes first seen (%s)", p.LastSeen, p.FirstSeen)
	}

	return &Installation{
		ID:             NewID(),
		AssetID:        p.AssetID,
		Vendor:         p.Vendor,
		Product:        p.Product,
		Version:        p.Version,
		Architecture:   p.Architecture,
		PackageManager: p.PackageManager,
		InstallPath:    p.InstallPath,
		CPE:            p.CPE,
		PURL:           p.PURL,
		FirstSeen:      p.FirstSeen,
		LastSeen:       p.LastSeen,
	}, nil
}

// Observe records that the installation was seen again at t, advancing
// LastSeen without ever moving it backwards (AGENTS.md §37 idempotency).
func (i *Installation) Observe(t time.Time) error {
	if t.Before(i.FirstSeen) {
		return fmt.Errorf("software: observed time (%s) precedes first seen (%s)", t, i.FirstSeen)
	}
	if t.After(i.LastSeen) {
		i.LastSeen = t
	}
	return nil
}
