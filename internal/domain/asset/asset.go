package asset

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/id"
)

// ID uniquely identifies an Asset.
type ID string

// NewID returns a new random Asset ID.
func NewID() ID {
	return ID(id.New())
}

// Asset is the central entity of the system (AGENTS.md §4): a piece of IT
// infrastructure that can carry Software, Findings, and business risk.
type Asset struct {
	ID              ID
	Hostname        string
	FQDN            string
	IPAddresses     []string
	MACAddresses    []string
	Type            Type
	OperatingSystem string
	Environment     Environment
	Owner           string
	BusinessUnit    string
	Criticality     Criticality
	Exposure        Exposure
	FirstSeen       time.Time
	LastSeen        time.Time
	LifecycleState  LifecycleState
}

// Params holds the fields needed to create a new Asset.
type Params struct {
	Hostname        string
	FQDN            string
	IPAddresses     []string
	MACAddresses    []string
	Type            Type
	OperatingSystem string
	Environment     Environment
	Owner           string
	BusinessUnit    string
	Criticality     Criticality
	Exposure        Exposure
	FirstSeen       time.Time
	LastSeen        time.Time
	LifecycleState  LifecycleState
}

// New creates an Asset from p, validating required fields and enums.
// Criticality is expected to come from business context (CMDB, asset
// register, business owner), not to be inferred here (AGENTS.md §11).
func New(p Params) (*Asset, error) {
	if strings.TrimSpace(p.Hostname) == "" {
		return nil, fmt.Errorf("asset: hostname is required")
	}
	if !p.Type.Valid() {
		return nil, fmt.Errorf("asset: invalid type %q", p.Type)
	}
	if !p.Environment.Valid() {
		return nil, fmt.Errorf("asset: invalid environment %q", p.Environment)
	}
	if !p.Criticality.Valid() {
		return nil, fmt.Errorf("asset: invalid criticality %q", p.Criticality)
	}
	if !p.LifecycleState.Valid() {
		return nil, fmt.Errorf("asset: invalid lifecycle state %q", p.LifecycleState)
	}
	if !p.Exposure.Level.Valid() {
		return nil, fmt.Errorf("asset: invalid exposure level %q", p.Exposure.Level)
	}
	if p.FirstSeen.IsZero() {
		return nil, fmt.Errorf("asset: first seen is required")
	}
	if p.LastSeen.IsZero() {
		p.LastSeen = p.FirstSeen
	}
	if p.LastSeen.Before(p.FirstSeen) {
		return nil, fmt.Errorf("asset: last seen (%s) precedes first seen (%s)", p.LastSeen, p.FirstSeen)
	}

	return &Asset{
		ID:              NewID(),
		Hostname:        p.Hostname,
		FQDN:            p.FQDN,
		IPAddresses:     p.IPAddresses,
		MACAddresses:    p.MACAddresses,
		Type:            p.Type,
		OperatingSystem: p.OperatingSystem,
		Environment:     p.Environment,
		Owner:           p.Owner,
		BusinessUnit:    p.BusinessUnit,
		Criticality:     p.Criticality,
		Exposure:        p.Exposure,
		FirstSeen:       p.FirstSeen,
		LastSeen:        p.LastSeen,
		LifecycleState:  p.LifecycleState,
	}, nil
}

// Observe records that the asset was seen again at t, advancing LastSeen.
// Repeated or out-of-order calls (AGENTS.md §37 idempotency) never move
// LastSeen backwards, and t may not precede FirstSeen.
func (a *Asset) Observe(t time.Time) error {
	if t.Before(a.FirstSeen) {
		return fmt.Errorf("asset: observed time (%s) precedes first seen (%s)", t, a.FirstSeen)
	}
	if t.After(a.LastSeen) {
		a.LastSeen = t
	}
	return nil
}
