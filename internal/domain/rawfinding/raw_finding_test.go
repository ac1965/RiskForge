package rawfinding

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func validParams() Params {
	return Params{
		Source:      "pownforge:nuclei",
		SourceRef:   "run-1:finding-1",
		AssetID:     asset.NewID(),
		EvidenceID:  evidence.NewID(),
		Title:       "Exposed Admin Panel",
		Detail:      "An admin panel was found exposed.",
		Confidence:  finding.ConfidenceMedium,
		CollectedAt: time.Now(),
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing source", mutate: func(p *Params) { p.Source = "" }, wantErr: true},
		{name: "missing asset id", mutate: func(p *Params) { p.AssetID = "" }, wantErr: true},
		{name: "missing title", mutate: func(p *Params) { p.Title = "" }, wantErr: true},
		{name: "missing collected at", mutate: func(p *Params) { p.CollectedAt = time.Time{} }, wantErr: true},
		{name: "invalid confidence", mutate: func(p *Params) { p.Confidence = "certain" }, wantErr: true},
		{
			name:   "missing confidence defaults to unknown",
			mutate: func(p *Params) { p.Confidence = "" },
		},
		{
			name:   "source ref is optional",
			mutate: func(p *Params) { p.SourceRef = "" },
		},
		{
			name:   "evidence id is optional",
			mutate: func(p *Params) { p.EvidenceID = "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)

			rf, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if rf.ID == "" {
				t.Error("New() did not assign an ID")
			}
		})
	}
}

func TestNewDefaultsMissingConfidenceToUnknown(t *testing.T) {
	p := validParams()
	p.Confidence = ""

	rf, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if rf.Confidence != finding.ConfidenceUnknown {
		t.Errorf("Confidence = %q, want %q", rf.Confidence, finding.ConfidenceUnknown)
	}
}

func TestNewCarriesOptionalCVSSFields(t *testing.T) {
	p := validParams()
	score := 9.8
	p.CVSSScore = &score
	p.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	p.NativeSeverity = "critical"
	p.AttackTechniqueIDs = []string{"T1190"}

	rf, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if rf.CVSSScore == nil || *rf.CVSSScore != 9.8 {
		t.Errorf("CVSSScore = %v, want 9.8", rf.CVSSScore)
	}
	if rf.CVSSVector != p.CVSSVector {
		t.Errorf("CVSSVector = %q, want %q", rf.CVSSVector, p.CVSSVector)
	}
	if rf.NativeSeverity != "critical" {
		t.Errorf("NativeSeverity = %q, want critical", rf.NativeSeverity)
	}
	if len(rf.AttackTechniqueIDs) != 1 || rf.AttackTechniqueIDs[0] != "T1190" {
		t.Errorf("AttackTechniqueIDs = %v, want [T1190]", rf.AttackTechniqueIDs)
	}
}
