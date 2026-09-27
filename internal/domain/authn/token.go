package authn

import (
	"fmt"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/id"
)

// TokenID uniquely identifies an APIToken.
type TokenID string

// NewTokenID returns a new random TokenID.
func NewTokenID() TokenID {
	return TokenID(id.New())
}

// ScopeRead is the only scope P0-2's read-only endpoints require (ADR
// 0012). Write-endpoint scopes (e.g. "remediation:approve") are added by
// the PR that implements the endpoint they gate, not speculatively here.
const ScopeRead = "read"

// APIToken is a bearer credential belonging to a Principal (ADR 0012).
// Only its SHA-256 hash (TokenHash, see HashToken) is ever held here or
// persisted — the raw token exists only at issuance time, in the CLI
// operator's terminal.
//
// ExpiresAt, RevokedAt, and LastUsedAt use the same "zero value means
// unset" convention as remediation.Plan's ScheduledAt/ExecutedAt, rather
// than *time.Time, to match this codebase's existing style.
type APIToken struct {
	ID          TokenID
	PrincipalID PrincipalID
	TokenHash   string
	Scopes      []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   time.Time
	LastUsedAt  time.Time
}

// APITokenParams holds the fields needed to create a new APIToken.
// ExpiresAt is optional (a zero value means the token never expires on
// its own and can only be ended by Revoke).
type APITokenParams struct {
	PrincipalID PrincipalID
	TokenHash   string
	Scopes      []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// NewAPIToken creates an APIToken from p, validating required fields.
func NewAPIToken(p APITokenParams) (*APIToken, error) {
	if strings.TrimSpace(string(p.PrincipalID)) == "" {
		return nil, fmt.Errorf("authn: token principal id is required")
	}
	if strings.TrimSpace(p.TokenHash) == "" {
		return nil, fmt.Errorf("authn: token hash is required")
	}
	if len(p.Scopes) == 0 {
		return nil, fmt.Errorf("authn: token must have at least one scope")
	}
	if p.CreatedAt.IsZero() {
		return nil, fmt.Errorf("authn: token created at is required")
	}
	if !p.ExpiresAt.IsZero() && !p.ExpiresAt.After(p.CreatedAt) {
		return nil, fmt.Errorf("authn: token expires at (%s) must be after created at (%s)", p.ExpiresAt, p.CreatedAt)
	}

	return &APIToken{
		ID:          NewTokenID(),
		PrincipalID: p.PrincipalID,
		TokenHash:   p.TokenHash,
		Scopes:      p.Scopes,
		CreatedAt:   p.CreatedAt,
		ExpiresAt:   p.ExpiresAt,
	}, nil
}

// Active reports whether the token is currently usable as of now: not
// revoked, and not past its expiry (a zero ExpiresAt never expires).
func (t *APIToken) Active(now time.Time) bool {
	if !t.RevokedAt.IsZero() {
		return false
	}
	if !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(now) {
		return false
	}
	return true
}

// HasScope reports whether the token carries scope.
func (t *APIToken) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Revoke ends the token's usability as of at, ahead of any natural
// expiry. Revoking an already-revoked token is idempotent (AGENTS.md
// §37): the original RevokedAt is kept, and no error is returned.
func (t *APIToken) Revoke(at time.Time) {
	if t.RevokedAt.IsZero() {
		t.RevokedAt = at
	}
}

// Touch records that the token was just used, advancing LastUsedAt.
// Mirrors asset.Observe's idempotency convention: repeated or
// out-of-order calls never move LastUsedAt backwards.
func (t *APIToken) Touch(at time.Time) {
	if at.After(t.LastUsedAt) {
		t.LastUsedAt = at
	}
}
