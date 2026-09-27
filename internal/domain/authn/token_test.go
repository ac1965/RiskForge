package authn

import (
	"testing"
	"time"
)

func mustToken(t *testing.T, expiresAt time.Time) *APIToken {
	t.Helper()
	tok, err := NewAPIToken(APITokenParams{
		PrincipalID: NewPrincipalID(),
		TokenHash:   HashToken("rf_test"),
		Scopes:      []string{ScopeRead},
		CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		t.Fatalf("NewAPIToken() unexpected error: %v", err)
	}
	return tok
}

func TestNewAPIToken_Validation(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		p    APITokenParams
	}{
		{"missing principal", APITokenParams{TokenHash: "h", Scopes: []string{ScopeRead}, CreatedAt: created}},
		{"missing hash", APITokenParams{PrincipalID: NewPrincipalID(), Scopes: []string{ScopeRead}, CreatedAt: created}},
		{"no scopes", APITokenParams{PrincipalID: NewPrincipalID(), TokenHash: "h", CreatedAt: created}},
		{"zero created at", APITokenParams{PrincipalID: NewPrincipalID(), TokenHash: "h", Scopes: []string{ScopeRead}}},
		{
			"expires before created",
			APITokenParams{
				PrincipalID: NewPrincipalID(), TokenHash: "h", Scopes: []string{ScopeRead},
				CreatedAt: created, ExpiresAt: created.Add(-time.Hour),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewAPIToken(c.p); err == nil {
				t.Error("NewAPIToken() expected an error, got nil")
			}
		})
	}
}

func TestAPIToken_Active(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	neverExpires := mustToken(t, time.Time{})
	if !neverExpires.Active(now) {
		t.Error("token with no expiry should be active")
	}

	future := mustToken(t, now.Add(time.Hour))
	if !future.Active(now) {
		t.Error("token expiring in the future should be active")
	}

	past := mustToken(t, now.Add(-time.Hour))
	if past.Active(now) {
		t.Error("token past its expiry should not be active")
	}

	revoked := mustToken(t, time.Time{})
	revoked.Revoke(now)
	if revoked.Active(now) {
		t.Error("revoked token should not be active")
	}
}

func TestAPIToken_RevokeIsIdempotent(t *testing.T) {
	tok := mustToken(t, time.Time{})
	first := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	second := first.Add(time.Hour)

	tok.Revoke(first)
	tok.Revoke(second)

	if !tok.RevokedAt.Equal(first) {
		t.Errorf("RevokedAt = %s, want first revocation time %s to stick", tok.RevokedAt, first)
	}
}

func TestAPIToken_HasScope(t *testing.T) {
	tok := mustToken(t, time.Time{})
	if !tok.HasScope(ScopeRead) {
		t.Error("expected token to have the read scope")
	}
	if tok.HasScope("remediation:approve") {
		t.Error("token should not have a scope it was never granted")
	}
}

func TestAPIToken_TouchNeverMovesBackwards(t *testing.T) {
	tok := mustToken(t, time.Time{})
	later := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	earlier := later.Add(-time.Hour)

	tok.Touch(later)
	tok.Touch(earlier)

	if !tok.LastUsedAt.Equal(later) {
		t.Errorf("LastUsedAt = %s, want %s (out-of-order Touch must not move it backwards)", tok.LastUsedAt, later)
	}
}

func TestGenerateRawTokenAndHashToken(t *testing.T) {
	raw1, err := GenerateRawToken()
	if err != nil {
		t.Fatalf("GenerateRawToken() unexpected error: %v", err)
	}
	raw2, err := GenerateRawToken()
	if err != nil {
		t.Fatalf("GenerateRawToken() unexpected error: %v", err)
	}
	if raw1 == raw2 {
		t.Error("GenerateRawToken() returned the same value twice")
	}
	if len(raw1) < len(tokenPrefix) || raw1[:len(tokenPrefix)] != tokenPrefix {
		t.Errorf("GenerateRawToken() = %q, want it to start with %q", raw1, tokenPrefix)
	}

	if HashToken(raw1) == HashToken(raw2) {
		t.Error("HashToken() collided for two different raw tokens")
	}
	if HashToken(raw1) != HashToken(raw1) {
		t.Error("HashToken() is not deterministic for the same input")
	}
}
