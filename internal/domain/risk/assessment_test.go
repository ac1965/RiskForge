package risk

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func validAssessmentParams() Params {
	return Params{
		FindingID:     finding.NewID(),
		Score:         42,
		Level:         LevelMedium,
		Factors:       []explainability.Factor{{Name: "severity", Value: "medium", Reason: "test"}},
		PolicyName:    "baseline",
		PolicyVersion: "1.0.0",
		AssessedAt:    time.Now(),
	}
}

func TestNewAssessment(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing finding id", mutate: func(p *Params) { p.FindingID = "" }, wantErr: true},
		{name: "score too low", mutate: func(p *Params) { p.Score = -1 }, wantErr: true},
		{name: "score too high", mutate: func(p *Params) { p.Score = 101 }, wantErr: true},
		{name: "invalid level", mutate: func(p *Params) { p.Level = "extreme" }, wantErr: true},
		{name: "no factors", mutate: func(p *Params) { p.Factors = nil }, wantErr: true},
		{
			name: "factor missing reason",
			mutate: func(p *Params) {
				p.Factors = []explainability.Factor{{Name: "x"}}
			},
			wantErr: true,
		},
		{name: "missing policy name", mutate: func(p *Params) { p.PolicyName = "" }, wantErr: true},
		{name: "missing assessed at", mutate: func(p *Params) { p.AssessedAt = time.Time{} }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validAssessmentParams()
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
		})
	}
}
