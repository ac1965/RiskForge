package application

import (
	"errors"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/authn"
)

func TestCreateAPIToken_FindOrCreatesPrincipal(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := t.Context()

	raw1, tok1, err := svc.CreateAPIToken(ctx, "dashboard", authn.KindService, []string{authn.ScopeRead}, time.Time{})
	if err != nil {
		t.Fatalf("CreateAPIToken() unexpected error: %v", err)
	}
	if raw1 == "" {
		t.Fatal("CreateAPIToken() returned an empty raw token")
	}

	raw2, tok2, err := svc.CreateAPIToken(ctx, "dashboard", authn.KindService, []string{authn.ScopeRead}, time.Time{})
	if err != nil {
		t.Fatalf("CreateAPIToken() second call unexpected error: %v", err)
	}
	if raw1 == raw2 {
		t.Error("two CreateAPIToken() calls returned the same raw token")
	}
	if tok1.PrincipalID != tok2.PrincipalID {
		t.Errorf("PrincipalID differs across calls with the same name: %s vs %s (want find-or-create to reuse the Principal)", tok1.PrincipalID, tok2.PrincipalID)
	}
	if len(repos.principals.byID) != 1 {
		t.Errorf("principals created = %d, want 1 (find-or-create should not duplicate)", len(repos.principals.byID))
	}

	// The persisted token never carries the raw value or anything that
	// reveals it (AGENTS.md §31).
	if tok1.TokenHash == raw1 {
		t.Error("APIToken.TokenHash equals the raw token; it must be hashed")
	}
}

func TestAuthenticateToken_Success(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()

	raw, tok, err := svc.CreateAPIToken(ctx, "dashboard", authn.KindService, []string{authn.ScopeRead}, time.Time{})
	if err != nil {
		t.Fatalf("CreateAPIToken() unexpected error: %v", err)
	}

	principal, scopes, err := svc.AuthenticateToken(ctx, raw)
	if err != nil {
		t.Fatalf("AuthenticateToken() unexpected error: %v", err)
	}
	if principal.ID != tok.PrincipalID {
		t.Errorf("AuthenticateToken() principal = %s, want %s", principal.ID, tok.PrincipalID)
	}
	if len(scopes) != 1 || scopes[0] != authn.ScopeRead {
		t.Errorf("AuthenticateToken() scopes = %v, want [%s]", scopes, authn.ScopeRead)
	}
}

func TestAuthenticateToken_RejectsUnknownEmptyAndRevoked(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()

	if _, _, err := svc.AuthenticateToken(ctx, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("AuthenticateToken(\"\") error = %v, want ErrUnauthenticated", err)
	}
	if _, _, err := svc.AuthenticateToken(ctx, "rf_does-not-exist"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("AuthenticateToken() with unknown token error = %v, want ErrUnauthenticated", err)
	}

	raw, tok, err := svc.CreateAPIToken(ctx, "dashboard", authn.KindService, []string{authn.ScopeRead}, time.Time{})
	if err != nil {
		t.Fatalf("CreateAPIToken() unexpected error: %v", err)
	}
	if _, err := svc.RevokeAPIToken(ctx, tok.ID); err != nil {
		t.Fatalf("RevokeAPIToken() unexpected error: %v", err)
	}
	if _, _, err := svc.AuthenticateToken(ctx, raw); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("AuthenticateToken() with revoked token error = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthenticateToken_RejectsExpired(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := t.Context()

	// CreateAPIToken (and authn.NewAPIToken underneath it) rejects an
	// expiresAt that is already in the past *at issuance time* — that is
	// invalid input, not the scenario this test wants. The real "expired
	// token" case is a token that was validly issued with a future
	// expiry which has since passed, so it is built directly against the
	// fakes here rather than through CreateAPIToken.
	issuedAt := time.Now().Add(-2 * time.Hour)
	expiredAt := time.Now().Add(-time.Hour)

	principal, err := authn.NewPrincipal(authn.PrincipalParams{Name: "dashboard", Kind: authn.KindService, CreatedAt: issuedAt})
	if err != nil {
		t.Fatalf("NewPrincipal() unexpected error: %v", err)
	}
	if err := repos.principals.Save(ctx, principal); err != nil {
		t.Fatalf("save principal: %v", err)
	}

	raw, err := authn.GenerateRawToken()
	if err != nil {
		t.Fatalf("GenerateRawToken() unexpected error: %v", err)
	}
	tok, err := authn.NewAPIToken(authn.APITokenParams{
		PrincipalID: principal.ID,
		TokenHash:   authn.HashToken(raw),
		Scopes:      []string{authn.ScopeRead},
		CreatedAt:   issuedAt,
		ExpiresAt:   expiredAt,
	})
	if err != nil {
		t.Fatalf("NewAPIToken() unexpected error: %v", err)
	}
	if err := repos.apiTokens.Save(ctx, tok); err != nil {
		t.Fatalf("save token: %v", err)
	}

	if _, _, err := svc.AuthenticateToken(ctx, raw); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("AuthenticateToken() with an already-expired token error = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthenticateToken_TouchesLastUsedAt(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := t.Context()

	raw, tok, err := svc.CreateAPIToken(ctx, "dashboard", authn.KindService, []string{authn.ScopeRead}, time.Time{})
	if err != nil {
		t.Fatalf("CreateAPIToken() unexpected error: %v", err)
	}
	if !tok.LastUsedAt.IsZero() {
		t.Fatalf("newly created token already has LastUsedAt = %s", tok.LastUsedAt)
	}

	if _, _, err := svc.AuthenticateToken(ctx, raw); err != nil {
		t.Fatalf("AuthenticateToken() unexpected error: %v", err)
	}

	stored, err := repos.apiTokens.FindByID(ctx, tok.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if stored.LastUsedAt.IsZero() {
		t.Error("AuthenticateToken() did not record LastUsedAt")
	}
}

func TestRevokeAPIToken_UnknownIsError(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()

	if _, err := svc.RevokeAPIToken(ctx, authn.NewTokenID()); err == nil {
		t.Error("RevokeAPIToken() with an unknown id: want error, got nil")
	}
}

func TestListAPITokens(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()

	if _, _, err := svc.CreateAPIToken(ctx, "dashboard", authn.KindService, []string{authn.ScopeRead}, time.Time{}); err != nil {
		t.Fatalf("CreateAPIToken() unexpected error: %v", err)
	}

	tokens, err := svc.ListAPITokens(ctx)
	if err != nil {
		t.Fatalf("ListAPITokens() unexpected error: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("ListAPITokens() returned %d tokens, want 1", len(tokens))
	}
}
