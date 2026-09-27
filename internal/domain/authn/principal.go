package authn

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/id"
)

// PrincipalID uniquely identifies a Principal.
type PrincipalID string

// NewPrincipalID returns a new random PrincipalID.
func NewPrincipalID() PrincipalID {
	return PrincipalID(id.New())
}

// Kind distinguishes a human operator from a service/automation caller.
type Kind string

const (
	KindHuman   Kind = "human"
	KindService Kind = "service"
)

// Valid reports whether k is one of the defined kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindHuman, KindService:
		return true
	}
	return false
}

// Principal is "who" issued an authenticated HTTP API request — a human
// operator or a service account (ADR 0012). It carries no credentials
// itself; that is APIToken's job.
type Principal struct {
	ID        PrincipalID
	Name      string
	Kind      Kind
	CreatedAt time.Time
}

// PrincipalParams holds the fields needed to create a new Principal.
type PrincipalParams struct {
	Name      string
	Kind      Kind
	CreatedAt time.Time
}

// NewPrincipal creates a Principal from p, validating required fields.
func NewPrincipal(p PrincipalParams) (*Principal, error) {
	if strings.TrimSpace(p.Name) == "" {
		return nil, fmt.Errorf("authn: principal name is required")
	}
	if !p.Kind.Valid() {
		return nil, fmt.Errorf("authn: invalid principal kind %q", p.Kind)
	}
	if p.CreatedAt.IsZero() {
		return nil, fmt.Errorf("authn: principal created at is required")
	}

	return &Principal{
		ID:        NewPrincipalID(),
		Name:      p.Name,
		Kind:      p.Kind,
		CreatedAt: p.CreatedAt,
	}, nil
}
