package asset

import (
	"testing"
	"time"
)

func validParams() Params {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return Params{
		Hostname:       "web-01",
		Type:           TypeServer,
		Environment:    EnvironmentProduction,
		Criticality:    CriticalityCritical,
		Exposure:       Exposure{Level: LevelDirect, InternetExposed: true},
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: LifecycleActive,
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing hostname", mutate: func(p *Params) { p.Hostname = "  " }, wantErr: true},
		{name: "invalid type", mutate: func(p *Params) { p.Type = "printer" }, wantErr: true},
		{name: "invalid environment", mutate: func(p *Params) { p.Environment = "prod" }, wantErr: true},
		{name: "invalid criticality", mutate: func(p *Params) { p.Criticality = "urgent" }, wantErr: true},
		{name: "invalid lifecycle state", mutate: func(p *Params) { p.LifecycleState = "zombie" }, wantErr: true},
		{name: "invalid exposure level", mutate: func(p *Params) { p.Exposure.Level = "sorta" }, wantErr: true},
		{name: "missing first seen", mutate: func(p *Params) { p.FirstSeen = time.Time{} }, wantErr: true},
		{
			name: "last seen before first seen",
			mutate: func(p *Params) {
				p.LastSeen = p.FirstSeen.Add(-time.Hour)
			},
			wantErr: true,
		},
		{
			name: "last seen defaults to first seen",
			mutate: func(p *Params) {
				p.LastSeen = time.Time{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)

			a, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if a.ID == "" {
				t.Error("New() did not assign an ID")
			}
			if a.LastSeen.Before(a.FirstSeen) {
				t.Errorf("LastSeen %s before FirstSeen %s", a.LastSeen, a.FirstSeen)
			}
		})
	}
}

func TestAssetObserve(t *testing.T) {
	p := validParams()
	a, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	earlier := a.FirstSeen.Add(-time.Hour)
	if err := a.Observe(earlier); err == nil {
		t.Error("Observe() with time before FirstSeen: want error, got nil")
	}

	later := a.LastSeen.Add(time.Hour)
	if err := a.Observe(later); err != nil {
		t.Fatalf("Observe() unexpected error: %v", err)
	}
	if !a.LastSeen.Equal(later) {
		t.Errorf("LastSeen = %s, want %s", a.LastSeen, later)
	}

	// Observing an earlier-but-valid time must not regress LastSeen
	// (idempotency, AGENTS.md §37).
	if err := a.Observe(a.FirstSeen); err != nil {
		t.Fatalf("Observe() unexpected error: %v", err)
	}
	if !a.LastSeen.Equal(later) {
		t.Errorf("LastSeen regressed to %s, want %s", a.LastSeen, later)
	}
}

// Fixtures from AGENTS.md §36: a critical, internet-exposed production
// asset and a low-criticality, internal-only asset — used again once the
// Risk Engine exists, but validated here as constructible domain entities.
func TestFixtures(t *testing.T) {
	criticalExposed := validParams()
	criticalExposed.Criticality = CriticalityCritical
	criticalExposed.Environment = EnvironmentProduction
	criticalExposed.Exposure = Exposure{Level: LevelDirect, InternetExposed: true}
	if _, err := New(criticalExposed); err != nil {
		t.Fatalf("critical internet-exposed asset: unexpected error: %v", err)
	}

	lowInternal := validParams()
	lowInternal.Criticality = CriticalityLow
	lowInternal.Environment = EnvironmentDevelopment
	lowInternal.Exposure = Exposure{Level: LevelInternalOnly}
	if _, err := New(lowInternal); err != nil {
		t.Fatalf("low-criticality internal asset: unexpected error: %v", err)
	}
}
