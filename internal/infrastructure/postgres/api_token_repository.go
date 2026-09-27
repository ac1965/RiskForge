package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/authn"
)

// APITokenRepository implements application.APITokenRepository against
// PostgreSQL.
type APITokenRepository struct {
	db *sql.DB
}

// NewAPITokenRepository returns an APITokenRepository backed by db.
func NewAPITokenRepository(db *sql.DB) *APITokenRepository {
	return &APITokenRepository{db: db}
}

const apiTokenColumns = `
	id, principal_id, token_hash, scopes, created_at, expires_at,
	revoked_at, last_used_at`

// Save inserts t, or updates it in place if t.ID already exists.
func (r *APITokenRepository) Save(ctx context.Context, t *authn.APIToken) error {
	scopes, err := jsonStrings(t.Scopes)
	if err != nil {
		return fmt.Errorf("postgres: marshal token scopes: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO api_tokens (`+apiTokenColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (id) DO UPDATE SET
			principal_id = EXCLUDED.principal_id,
			token_hash = EXCLUDED.token_hash,
			scopes = EXCLUDED.scopes,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at,
			revoked_at = EXCLUDED.revoked_at,
			last_used_at = EXCLUDED.last_used_at
	`,
		t.ID, t.PrincipalID, t.TokenHash, scopes, t.CreatedAt,
		nullTime(t.ExpiresAt), nullTime(t.RevokedAt), nullTime(t.LastUsedAt),
	)
	if err != nil {
		return fmt.Errorf("postgres: save api token %s: %w", t.ID, err)
	}
	return nil
}

func scanAPIToken(row rowScanner) (*authn.APIToken, error) {
	var t authn.APIToken
	var scopes []byte
	var expiresAt, revokedAt, lastUsedAt sql.NullTime

	err := row.Scan(
		&t.ID, &t.PrincipalID, &t.TokenHash, &scopes, &t.CreatedAt,
		&expiresAt, &revokedAt, &lastUsedAt,
	)
	if err != nil {
		return nil, err
	}

	t.Scopes, err = scanStrings(scopes)
	if err != nil {
		return nil, err
	}
	t.ExpiresAt = fromNullTime(expiresAt)
	t.RevokedAt = fromNullTime(revokedAt)
	t.LastUsedAt = fromNullTime(lastUsedAt)

	return &t, nil
}

// FindByID returns the APIToken with the given id, or (nil, nil) if none
// exists.
func (r *APITokenRepository) FindByID(ctx context.Context, id authn.TokenID) (*authn.APIToken, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens WHERE id = $1`, id)
	t, err := scanAPIToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find api token %s: %w", id, err)
	}
	return t, nil
}

// FindByTokenHash returns the APIToken whose TokenHash matches hash, or
// (nil, nil) if none exists — AuthenticateToken's lookup key.
func (r *APITokenRepository) FindByTokenHash(ctx context.Context, hash string) (*authn.APIToken, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens WHERE token_hash = $1`, hash)
	t, err := scanAPIToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find api token by hash: %w", err)
	}
	return t, nil
}

// List returns every APIToken, most recently created first.
func (r *APITokenRepository) List(ctx context.Context) ([]*authn.APIToken, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list api tokens: %w", err)
	}
	defer rows.Close()

	var out []*authn.APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan api token: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list api tokens: %w", err)
	}
	return out, nil
}
