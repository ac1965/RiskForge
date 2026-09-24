package exception

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

func validParams() Params {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return Params{
		FindingID:           finding.NewID(),
		Reason:              "Confirmed false positive after manual review",
		RequestedBy:         "alice",
		CreatedAt:           created,
		ExpiresAt:           created.Add(90 * 24 * time.Hour),
		CompensatingControl: "WAF rule blocking the affected endpoint",
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
		{name: "missing reason", mutate: func(p *Params) { p.Reason = "" }, wantErr: true},
		{name: "missing requested by", mutate: func(p *Params) { p.RequestedBy = "" }, wantErr: true},
		{name: "missing created at", mutate: func(p *Params) { p.CreatedAt = time.Time{} }, wantErr: true},
		{
			name:    "missing expires at (no permanent exceptions)",
			mutate:  func(p *Params) { p.ExpiresAt = time.Time{} },
			wantErr: true,
		},
		{
			name:    "expires at before created at",
			mutate:  func(p *Params) { p.ExpiresAt = p.CreatedAt.Add(-time.Hour) },
			wantErr: true,
		},
		{
			name:   "compensating control is optional",
			mutate: func(p *Params) { p.CompensatingControl = "" },
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
			if e.Status != StatusRequested {
				t.Errorf("Status = %q, want %q", e.Status, StatusRequested)
			}
		})
	}
}

func TestTransitions(t *testing.T) {
	tests := []struct {
		from    Status
		to      Status
		wantErr bool
	}{
		{StatusRequested, StatusApproved, false},
		{StatusRequested, StatusRejected, false},
		{StatusRequested, StatusExpired, true},
		{StatusRequested, StatusRevoked, true},
		{StatusApproved, StatusExpired, false},
		{StatusApproved, StatusRevoked, false},
		{StatusApproved, StatusRejected, true},
		{StatusRejected, StatusApproved, true},
		{StatusExpired, StatusApproved, true},
		{StatusRevoked, StatusApproved, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.from)+"->"+string(tt.to), func(t *testing.T) {
			e, err := New(validParams())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.Status = tt.from

			var actionErr error
			switch tt.to {
			case StatusApproved:
				actionErr = e.Approve("bob")
			case StatusRejected:
				actionErr = e.Reject()
			case StatusExpired:
				actionErr = e.Expire()
			case StatusRevoked:
				actionErr = e.Revoke()
			}

			if tt.wantErr {
				if actionErr == nil {
					t.Fatalf("transition %s -> %s: error = nil, want error", tt.from, tt.to)
				}
				if e.Status != tt.from {
					t.Errorf("Status changed to %s after rejected transition, want unchanged %s", e.Status, tt.from)
				}
				return
			}
			if actionErr != nil {
				t.Fatalf("transition %s -> %s: unexpected error: %v", tt.from, tt.to, actionErr)
			}
			if e.Status != tt.to {
				t.Errorf("Status = %s, want %s", e.Status, tt.to)
			}
		})
	}
}

func TestIsActiveAndIsExpired(t *testing.T) {
	p := validParams()
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	beforeExpiry := p.ExpiresAt.Add(-time.Hour)
	afterExpiry := p.ExpiresAt.Add(time.Hour)

	if e.IsActive(beforeExpiry) {
		t.Error("IsActive() before approval = true, want false")
	}

	if err := e.Approve("bob"); err != nil {
		t.Fatalf("Approve() unexpected error: %v", err)
	}

	if !e.IsActive(beforeExpiry) {
		t.Error("IsActive() approved and before expiry = false, want true")
	}
	if e.IsExpired(beforeExpiry) {
		t.Error("IsExpired() before expiry = true, want false")
	}
	if e.IsActive(afterExpiry) {
		t.Error("IsActive() approved but past expiry = true, want false")
	}
	if !e.IsExpired(afterExpiry) {
		t.Error("IsExpired() past expiry = false, want true")
	}
}

// TestImpliedFindingStatus is the AGENTS.md §18 scenario: approval accepts
// the Finding, while expiry or revocation reopens it for re-evaluation; a
// rejected request never touched the Finding's status in the first place.
func TestImpliedFindingStatus(t *testing.T) {
	tests := []struct {
		status    Status
		wantApply bool
		want      finding.Status
	}{
		{StatusRequested, false, ""},
		{StatusApproved, true, finding.StatusAccepted},
		{StatusRejected, false, ""},
		{StatusExpired, true, finding.StatusReopened},
		{StatusRevoked, true, finding.StatusReopened},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			e, err := New(validParams())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.Status = tt.status

			status, apply := e.ImpliedFindingStatus()
			if apply != tt.wantApply {
				t.Errorf("apply = %v, want %v", apply, tt.wantApply)
			}
			if apply && status != tt.want {
				t.Errorf("status = %s, want %s", status, tt.want)
			}
		})
	}
}
