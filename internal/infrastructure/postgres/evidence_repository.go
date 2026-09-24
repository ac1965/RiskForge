package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

// EvidenceRepository implements application.EvidenceRepository against
// PostgreSQL.
type EvidenceRepository struct {
	db *sql.DB
}

// NewEvidenceRepository returns an EvidenceRepository backed by db.
func NewEvidenceRepository(db *sql.DB) *EvidenceRepository {
	return &EvidenceRepository{db: db}
}

// Save inserts e. Evidence is immutable (AGENTS.md §17, §22, §47.10): this
// is INSERT ... ON CONFLICT DO NOTHING, never an UPDATE — a retried Save
// of the same Evidence is a harmless no-op, but there is no path here
// that changes an existing row's contents.
func (r *EvidenceRepository) Save(ctx context.Context, e *evidence.Evidence) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO evidence (id, type, source, collected_at, asset_id, finding_id, content_hash, location)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (id) DO NOTHING
	`, e.ID, e.Type, e.Source, e.CollectedAt, e.AssetID, nullString(string(e.FindingID)), e.ContentHash, e.Location)
	if err != nil {
		return fmt.Errorf("postgres: save evidence %s: %w", e.ID, err)
	}
	return nil
}

// FindByID returns the Evidence with the given id, or (nil, nil) if none
// exists.
func (r *EvidenceRepository) FindByID(ctx context.Context, id evidence.ID) (*evidence.Evidence, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, type, source, collected_at, asset_id, finding_id, content_hash, location
		FROM evidence WHERE id = $1
	`, id)

	var e evidence.Evidence
	var findingID sql.NullString
	err := row.Scan(&e.ID, &e.Type, &e.Source, &e.CollectedAt, &e.AssetID, &findingID, &e.ContentHash, &e.Location)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find evidence %s: %w", id, err)
	}
	e.FindingID = finding.ID(fromNullString(findingID))
	return &e, nil
}
