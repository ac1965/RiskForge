package priority

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/risk"
)

func validDecisionParams() Params {
	now := time.Now()
	return Params{
		FindingID:        finding.NewID(),
		RiskAssessmentID: risk.NewID(),
		Rank:             50,
		Level:            LevelMedium,
		Factors:          []explainability.Factor{{Name: "risk_score", Value: "50", Reason: "test"}},
		SLADeadline:      now.Add(30 * 24 * time.Hour),
		PolicyName:       "baseline",
		PolicyVersion:    "1.0.0",
		DecidedAt:        now,
	}
}

func TestNewDecision(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing finding id", mutate: func(p *Params) { p.FindingID = "" }, wantErr: true},
		{name: "missing risk assessment id", mutate: func(p *Params) { p.RiskAssessmentID = "" }, wantErr: true},
		{name: "rank too low", mutate: func(p *Params) { p.Rank = -1 }, wantErr: true},
		{name: "rank too high", mutate: func(p *Params) { p.Rank = 101 }, wantErr: true},
		{name: "invalid level", mutate: func(p *Params) { p.Level = "extreme" }, wantErr: true},
		{name: "no factors", mutate: func(p *Params) { p.Factors = nil }, wantErr: true},
		{name: "missing policy name", mutate: func(p *Params) { p.PolicyName = "" }, wantErr: true},
		{name: "missing sla deadline", mutate: func(p *Params) { p.SLADeadline = time.Time{} }, wantErr: true},
		{name: "missing decided at", mutate: func(p *Params) { p.DecidedAt = time.Time{} }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validDecisionParams()
			tt.mutate(&p)

			d, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if d.ID == "" {
				t.Error("New() did not assign an ID")
			}
		})
	}
}
