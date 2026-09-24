package finding

import (
	"errors"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

func validParams() Params {
	return Params{
		AssetID:         asset.NewID(),
		VulnerabilityID: vulnerability.NewID(),
		DetectionSource: "nessus",
		DetectedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Confidence:      ConfidenceHigh,
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
		{name: "missing vulnerability id", mutate: func(p *Params) { p.VulnerabilityID = "" }, wantErr: true},
		{name: "missing detection source", mutate: func(p *Params) { p.DetectionSource = "" }, wantErr: true},
		{name: "missing detected at", mutate: func(p *Params) { p.DetectedAt = time.Time{} }, wantErr: true},
		{name: "invalid confidence", mutate: func(p *Params) { p.Confidence = "certain" }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)

			f, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if f.ID == "" {
				t.Error("New() did not assign an ID")
			}
			if f.Status != StatusOpen {
				t.Errorf("Status = %q, want %q", f.Status, StatusOpen)
			}
		})
	}
}

func TestFindingConfirm(t *testing.T) {
	f, err := New(validParams())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if err := f.Confirm(f.DetectedAt.Add(-time.Hour)); err == nil {
		t.Error("Confirm() before DetectedAt: want error, got nil")
	}

	later := f.DetectedAt.Add(48 * time.Hour)
	if err := f.Confirm(later); err != nil {
		t.Fatalf("Confirm() unexpected error: %v", err)
	}
	if !f.LastConfirmedAt.Equal(later) {
		t.Errorf("LastConfirmedAt = %s, want %s", f.LastConfirmedAt, later)
	}
}

func TestTransitionTo(t *testing.T) {
	tests := []struct {
		from    Status
		to      Status
		wantErr bool
	}{
		{from: StatusOpen, to: StatusMitigated},
		{from: StatusOpen, to: StatusRemediated},
		{from: StatusOpen, to: StatusAccepted},
		{from: StatusOpen, to: StatusFalsePositive},
		{from: StatusOpen, to: StatusVerified, wantErr: true}, // Invariant 6: must remediate first
		{from: StatusMitigated, to: StatusVerified, wantErr: true},
		{from: StatusMitigated, to: StatusRemediated},
		{from: StatusRemediated, to: StatusVerified},
		{from: StatusRemediated, to: StatusReopened},
		{from: StatusVerified, to: StatusReopened},
		{from: StatusVerified, to: StatusMitigated, wantErr: true},
		{from: StatusAccepted, to: StatusReopened},
		{from: StatusFalsePositive, to: StatusReopened},
		{from: StatusOpen, to: StatusOpen}, // no-op
		{from: StatusOpen, to: "bogus", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(string(tt.from)+"->"+string(tt.to), func(t *testing.T) {
			f, err := New(validParams())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			f.Status = tt.from

			err = f.TransitionTo(tt.to)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("TransitionTo(%s) from %s: error = nil, want error", tt.to, tt.from)
				}
				if tt.to.Valid() && !errors.Is(err, ErrInvalidTransition) {
					t.Errorf("TransitionTo() error = %v, want wrapping ErrInvalidTransition", err)
				}
				if f.Status != tt.from {
					t.Errorf("Status changed to %s after rejected transition, want unchanged %s", f.Status, tt.from)
				}
				return
			}
			if err != nil {
				t.Fatalf("TransitionTo(%s) from %s: unexpected error: %v", tt.to, tt.from, err)
			}
			if f.Status != tt.to {
				t.Errorf("Status = %s, want %s", f.Status, tt.to)
			}
		})
	}
}

// Fixtures from AGENTS.md §36: an internet-exposed asset with a known
// exploited vulnerability, and an internal-only asset with no exploit —
// exercised here as constructible Findings ahead of the Risk Engine.
func TestFixtures(t *testing.T) {
	exposedAssetID := asset.NewID()
	kevVulnID := vulnerability.NewID()

	exposed, err := New(Params{
		AssetID:         exposedAssetID,
		VulnerabilityID: kevVulnID,
		DetectionSource: "riskforge-agent",
		DetectedAt:      time.Now(),
		Confidence:      ConfidenceConfirmed,
	})
	if err != nil {
		t.Fatalf("internet-exposed + KEV finding: unexpected error: %v", err)
	}
	if exposed.Status != StatusOpen {
		t.Errorf("Status = %s, want %s", exposed.Status, StatusOpen)
	}

	internalAssetID := asset.NewID()
	noExploitVulnID := vulnerability.NewID()

	internal, err := New(Params{
		AssetID:         internalAssetID,
		VulnerabilityID: noExploitVulnID,
		DetectionSource: "riskforge-agent",
		DetectedAt:      time.Now(),
		Confidence:      ConfidenceMedium,
	})
	if err != nil {
		t.Fatalf("internal-only + no-exploit finding: unexpected error: %v", err)
	}
	if internal.Status != StatusOpen {
		t.Errorf("Status = %s, want %s", internal.Status, StatusOpen)
	}
}
