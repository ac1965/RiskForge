package authn

import (
	"testing"
	"time"
)

func TestNewPrincipal(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	p, err := NewPrincipal(PrincipalParams{Name: "dashboard", Kind: KindService, CreatedAt: now})
	if err != nil {
		t.Fatalf("NewPrincipal() unexpected error: %v", err)
	}
	if p.ID == "" {
		t.Error("NewPrincipal() did not assign an ID")
	}
	if p.Name != "dashboard" || p.Kind != KindService || !p.CreatedAt.Equal(now) {
		t.Errorf("NewPrincipal() = %+v, want name=dashboard kind=service createdAt=%s", p, now)
	}
}

func TestNewPrincipal_Validation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		p    PrincipalParams
	}{
		{"empty name", PrincipalParams{Name: "  ", Kind: KindHuman, CreatedAt: now}},
		{"invalid kind", PrincipalParams{Name: "alice", Kind: "robot", CreatedAt: now}},
		{"zero created at", PrincipalParams{Name: "alice", Kind: KindHuman}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPrincipal(c.p); err == nil {
				t.Error("NewPrincipal() expected an error, got nil")
			}
		})
	}
}
