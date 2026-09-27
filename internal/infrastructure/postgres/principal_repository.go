package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/authn"
)

// PrincipalRepository implements application.PrincipalRepository against
// PostgreSQL.
type PrincipalRepository struct {
	db *sql.DB
}

// NewPrincipalRepository returns a PrincipalRepository backed by db.
func NewPrincipalRepository(db *sql.DB) *PrincipalRepository {
	return &PrincipalRepository{db: db}
}

const principalColumns = `id, name, kind, created_at`

// Save inserts p, or updates it in place if p.ID already exists.
func (r *PrincipalRepository) Save(ctx context.Context, p *authn.Principal) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO principals (`+principalColumns+`)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			kind = EXCLUDED.kind,
			created_at = EXCLUDED.created_at
	`, p.ID, p.Name, p.Kind, p.CreatedAt)
	if err != nil {
		return fmt.Errorf("postgres: save principal %s: %w", p.ID, err)
	}
	return nil
}

func scanPrincipal(row rowScanner) (*authn.Principal, error) {
	var p authn.Principal
	if err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.CreatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// FindByID returns the Principal with the given id, or (nil, nil) if none
// exists.
func (r *PrincipalRepository) FindByID(ctx context.Context, id authn.PrincipalID) (*authn.Principal, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+principalColumns+` FROM principals WHERE id = $1`, id)
	p, err := scanPrincipal(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find principal %s: %w", id, err)
	}
	return p, nil
}

// FindByName returns the Principal with the given name, or (nil, nil) if
// none exists — CreateAPIToken's find-or-create key.
func (r *PrincipalRepository) FindByName(ctx context.Context, name string) (*authn.Principal, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+principalColumns+` FROM principals WHERE name = $1`, name)
	p, err := scanPrincipal(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find principal by name %q: %w", name, err)
	}
	return p, nil
}
