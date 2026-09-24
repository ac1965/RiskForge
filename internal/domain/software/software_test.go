package software

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
)

func validParams() Params {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return Params{
		AssetID:   asset.NewID(),
		Vendor:    "openssl",
		Product:   "openssl",
		Version:   "3.0.13",
		CPE:       "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		FirstSeen: now,
		LastSeen:  now,
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing asset id", mutate: func(p *Params) { p.AssetID = "" }, wantErr: true},
		{name: "missing vendor", mutate: func(p *Params) { p.Vendor = "" }, wantErr: true},
		{name: "missing product", mutate: func(p *Params) { p.Product = "" }, wantErr: true},
		{name: "missing version", mutate: func(p *Params) { p.Version = "" }, wantErr: true},
		{name: "missing first seen", mutate: func(p *Params) { p.FirstSeen = time.Time{} }, wantErr: true},
		{
			name:    "last seen before first seen",
			mutate:  func(p *Params) { p.LastSeen = p.FirstSeen.Add(-time.Hour) },
			wantErr: true,
		},
		{
			name:   "CPE and PURL are optional",
			mutate: func(p *Params) { p.CPE = ""; p.PURL = "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)

			inst, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if inst.ID == "" {
				t.Error("New() did not assign an ID")
			}
		})
	}
}

func TestInstallationObserve(t *testing.T) {
	inst, err := New(validParams())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if err := inst.Observe(inst.FirstSeen.Add(-time.Hour)); err == nil {
		t.Error("Observe() before FirstSeen: want error, got nil")
	}

	later := inst.LastSeen.Add(24 * time.Hour)
	if err := inst.Observe(later); err != nil {
		t.Fatalf("Observe() unexpected error: %v", err)
	}
	if !inst.LastSeen.Equal(later) {
		t.Errorf("LastSeen = %s, want %s", inst.LastSeen, later)
	}
}
