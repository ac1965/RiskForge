package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ac1965/riskforge/internal/domain/authn"
)

// ErrUnauthenticated is returned by AuthenticateToken when rawToken is
// missing, unknown, expired, or revoked. internal/api's RequireScope
// middleware maps this to 401; any other error it treats as a 500
// (ADR 0011's error-handling convention). It intentionally does not
// distinguish "no such token" from "expired" from "revoked" — an
// attacker probing the API should not be able to tell those apart
// either.
var ErrUnauthenticated = errors.New("application: invalid or expired token")

// CreateAPIToken is the `token create` Named API (ADR 0012). It attaches
// the new token to the Principal named principalName, creating that
// Principal first if none exists yet (find-or-create by name, so
// reissuing a token for the same service never duplicates the
// Principal). expiresAt may be zero for a token that never expires on
// its own. It returns the raw bearer token exactly once — RiskForge
// never stores or reconstructs it afterward — alongside the persisted
// (hashed) APIToken record. It is not audited: token issuance is not
// among AGENTS.md §30's enumerated audit actions (see
// docs/adr/0008-application-layer.md's rationale for the same choice on
// RejectException/RevokeException).
func (s *Service) CreateAPIToken(ctx context.Context, principalName string, kind authn.Kind, scopes []string, expiresAt time.Time) (rawToken string, token *authn.APIToken, err error) {
	now := time.Now()

	principal, err := s.Principals.FindByName(ctx, principalName)
	if err != nil {
		return "", nil, fmt.Errorf("application: find principal %q: %w", principalName, err)
	}
	if principal == nil {
		principal, err = authn.NewPrincipal(authn.PrincipalParams{Name: principalName, Kind: kind, CreatedAt: now})
		if err != nil {
			return "", nil, fmt.Errorf("application: create principal: %w", err)
		}
		if err := s.Principals.Save(ctx, principal); err != nil {
			return "", nil, fmt.Errorf("application: save principal %s: %w", principal.ID, err)
		}
	}

	raw, err := authn.GenerateRawToken()
	if err != nil {
		return "", nil, fmt.Errorf("application: generate token: %w", err)
	}

	t, err := authn.NewAPIToken(authn.APITokenParams{
		PrincipalID: principal.ID,
		TokenHash:   authn.HashToken(raw),
		Scopes:      scopes,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		return "", nil, fmt.Errorf("application: create token: %w", err)
	}
	if err := s.APITokens.Save(ctx, t); err != nil {
		return "", nil, fmt.Errorf("application: save token %s: %w", t.ID, err)
	}

	return raw, t, nil
}

// ListAPITokens returns every APIToken's metadata (never a raw token,
// which is never stored in the first place), for `riskforge token list`.
func (s *Service) ListAPITokens(ctx context.Context) ([]*authn.APIToken, error) {
	return s.APITokens.List(ctx)
}

// RevokeAPIToken ends tokenID's usability immediately, for `riskforge
// token revoke`. Revoking an already-revoked token is idempotent
// (authn.APIToken.Revoke); revoking a token that does not exist at all
// is an error.
func (s *Service) RevokeAPIToken(ctx context.Context, tokenID authn.TokenID) (*authn.APIToken, error) {
	t, err := s.APITokens.FindByID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("application: find token %s: %w", tokenID, err)
	}
	if t == nil {
		return nil, fmt.Errorf("application: token %s not found", tokenID)
	}

	t.Revoke(time.Now())
	if err := s.APITokens.Save(ctx, t); err != nil {
		return nil, fmt.Errorf("application: save token %s: %w", tokenID, err)
	}
	return t, nil
}

// AuthenticateToken resolves rawToken to the Principal that owns it and
// the scopes that specific token carries, for internal/api's
// RequireScope middleware. It also records the token's use (LastUsedAt).
//
// ADR 0012's own description says this call yields "Principal と
// scopes" for the middleware, but the ADR's literal Go signature named
// only *authn.Principal — an oversight the ADR's addendum corrects to
// match this implementation.
func (s *Service) AuthenticateToken(ctx context.Context, rawToken string) (*authn.Principal, []string, error) {
	if rawToken == "" {
		return nil, nil, ErrUnauthenticated
	}

	t, err := s.APITokens.FindByTokenHash(ctx, authn.HashToken(rawToken))
	if err != nil {
		return nil, nil, fmt.Errorf("application: find token by hash: %w", err)
	}
	now := time.Now()
	if t == nil || !t.Active(now) {
		return nil, nil, ErrUnauthenticated
	}

	principal, err := s.Principals.FindByID(ctx, t.PrincipalID)
	if err != nil {
		return nil, nil, fmt.Errorf("application: find principal %s: %w", t.PrincipalID, err)
	}
	if principal == nil {
		return nil, nil, ErrUnauthenticated
	}

	t.Touch(now)
	if err := s.APITokens.Save(ctx, t); err != nil {
		return nil, nil, fmt.Errorf("application: record token use: %w", err)
	}

	return principal, t.Scopes, nil
}
