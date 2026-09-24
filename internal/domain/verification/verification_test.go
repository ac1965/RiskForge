package verification

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func validParams() Params {
	return Params{
		FindingID:  finding.NewID(),
		Method:     MethodVersionCheck,
		VerifiedAt: time.Now(),
		Result:     ResultPass,
		EvidenceID: evidence.NewID(),
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *Params) {}},
		{name: "missing finding id", mutate: func(p *Params) { p.FindingID = "" }, wantErr: true},
		{name: "invalid method", mutate: func(p *Params) { p.Method = "vibes_check" }, wantErr: true},
		{name: "missing verified at", mutate: func(p *Params) { p.VerifiedAt = time.Time{} }, wantErr: true},
		{name: "invalid result", mutate: func(p *Params) { p.Result = "maybe" }, wantErr: true},
		{name: "missing evidence id", mutate: func(p *Params) { p.EvidenceID = "" }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutate(&p)

			v, err := New(p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if v.ID == "" {
				t.Error("New() did not assign an ID")
			}
		})
	}
}

// TestImpliedFindingStatus is the AGENTS.md §20A.6.1 scenario: an
// inconclusive verification (e.g. the asset was unreachable) must never
// be treated as if the vulnerability were still present.
func TestImpliedFindingStatus(t *testing.T) {
	tests := []struct {
		result    Result
		wantApply bool
		want      finding.Status
	}{
		{ResultPass, true, finding.StatusVerified},
		{ResultFail, true, finding.StatusReopened},
		{ResultInconclusive, false, ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.result), func(t *testing.T) {
			p := validParams()
			p.Result = tt.result
			v, err := New(p)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			status, apply := v.ImpliedFindingStatus()
			if apply != tt.wantApply {
				t.Errorf("apply = %v, want %v", apply, tt.wantApply)
			}
			if apply && status != tt.want {
				t.Errorf("status = %s, want %s", status, tt.want)
			}
		})
	}
}

// TestVerifiedRequiresPriorRemediation confirms Invariant 6 (AGENTS.md
// §44) end-to-end: a Finding that was only ever Open cannot be moved to
// Verified just because a Verification says ResultPass — the Finding's
// own state machine (package finding) still requires Remediated first.
func TestVerifiedRequiresPriorRemediation(t *testing.T) {
	f, err := finding.New(finding.Params{
		AssetID:         "asset-1",
		VulnerabilityID: "vuln-1",
		DetectionSource: "test-scanner",
		DetectedAt:      time.Now(),
		Confidence:      finding.ConfidenceConfirmed,
	})
	if err != nil {
		t.Fatalf("finding.New() unexpected error: %v", err)
	}

	p := validParams()
	p.Result = ResultPass
	v, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	status, apply := v.ImpliedFindingStatus()
	if !apply {
		t.Fatal("ImpliedFindingStatus() apply = false, want true for ResultPass")
	}
	if err := f.TransitionTo(status); err == nil {
		t.Error("TransitionTo(Verified) from Open: want error, got nil")
	}
}
