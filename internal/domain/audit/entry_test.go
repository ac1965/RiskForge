package audit

import (
	"testing"
	"time"
)

func validParams() Params {
	return Params{
		Action:      ActionRemediationApproval,
		Who:         "bob",
		SubjectType: "remediation_plan",
		SubjectID:   "plan-123",
		What:        "Approved patch plan for CVE-2026-00001",
		Why:         "Reviewed and confirmed safe for the next maintenance window",
		Before:      `{"status":"proposed"}`,
		After:       `{"status":"approved","approved_by":"bob"}`,
		OccurredAt:  time.Now(),
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing action", mutate: func(p *Params) { p.Action = "" }, wantErr: true},
		{name: "missing who", mutate: func(p *Params) { p.Who = "" }, wantErr: true},
		{name: "missing subject type", mutate: func(p *Params) { p.SubjectType = "" }, wantErr: true},
		{name: "missing subject id", mutate: func(p *Params) { p.SubjectID = "" }, wantErr: true},
		{name: "missing what", mutate: func(p *Params) { p.What = "" }, wantErr: true},
		{name: "missing why", mutate: func(p *Params) { p.Why = "" }, wantErr: true},
		{name: "missing occurred at", mutate: func(p *Params) { p.OccurredAt = time.Time{} }, wantErr: true},
		{
			name: "before and after may both be empty",
			mutate: func(p *Params) {
				p.Before = ""
				p.After = ""
			},
		},
		{
			name:   "arbitrary action beyond the named constants is allowed",
			mutate: func(p *Params) { p.Action = "pownforge_import" },
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
