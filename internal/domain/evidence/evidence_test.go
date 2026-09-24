package evidence

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func validParams() Params {
	content := []byte("scan output")
	return Params{
		Type:        TypeDetectionResult,
		Source:      "nessus",
		CollectedAt: time.Now(),
		AssetID:     asset.NewID(),
		FindingID:   finding.NewID(),
		ContentHash: ComputeContentHash(content),
		Location:    "s3://evidence-bucket/2026/01/01/scan.json",
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing type", mutate: func(p *Params) { p.Type = "" }, wantErr: true},
		{name: "missing source", mutate: func(p *Params) { p.Source = "" }, wantErr: true},
		{name: "missing collected at", mutate: func(p *Params) { p.CollectedAt = time.Time{} }, wantErr: true},
		{name: "missing asset id", mutate: func(p *Params) { p.AssetID = "" }, wantErr: true},
		{name: "missing content hash", mutate: func(p *Params) { p.ContentHash = "" }, wantErr: true},
		{name: "missing location", mutate: func(p *Params) { p.Location = "" }, wantErr: true},
		{
			name:   "finding id is optional",
			mutate: func(p *Params) { p.FindingID = "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)

			e, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if e.ID == "" {
				t.Error("New() did not assign an ID")
			}
		})
	}
}

func TestVerifyContent(t *testing.T) {
	content := []byte("scan output")
	p := validParams()
	p.ContentHash = ComputeContentHash(content)

	e, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if !e.VerifyContent(content) {
		t.Error("VerifyContent() with unmodified content = false, want true")
	}
	if e.VerifyContent([]byte("tampered output")) {
		t.Error("VerifyContent() with tampered content = true, want false")
	}
}
