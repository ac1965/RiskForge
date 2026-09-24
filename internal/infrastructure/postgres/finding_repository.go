package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// FindingRepository implements application.FindingRepository against
// PostgreSQL.
type FindingRepository struct {
	db *sql.DB
}

// NewFindingRepository returns a FindingRepository backed by db.
func NewFindingRepository(db *sql.DB) *FindingRepository {
	return &FindingRepository{db: db}
}

const findingColumns = `
	id, asset_id, vulnerability_id, detection_source, detected_at,
	last_confirmed_at, status, confidence, evidence_id`

// Save inserts f, or updates it in place if f.ID already exists.
func (r *FindingRepository) Save(ctx context.Context, f *finding.Finding) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO findings (`+findingColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			asset_id = EXCLUDED.asset_id,
			vulnerability_id = EXCLUDED.vulnerability_id,
			detection_source = EXCLUDED.detection_source,
			detected_at = EXCLUDED.detected_at,
			last_confirmed_at = EXCLUDED.last_confirmed_at,
			status = EXCLUDED.status,
			confidence = EXCLUDED.confidence,
			evidence_id = EXCLUDED.evidence_id
	`,
		f.ID, f.AssetID, f.VulnerabilityID, f.DetectionSource, f.DetectedAt,
		f.LastConfirmedAt, f.Status, f.Confidence, nullString(f.EvidenceID),
	)
	if err != nil {
		return fmt.Errorf("postgres: save finding %s: %w", f.ID, err)
	}
	return nil
}

func scanFinding(row rowScanner) (*finding.Finding, error) {
	var f finding.Finding
	var evidenceID sql.NullString

	err := row.Scan(
		&f.ID, &f.AssetID, &f.VulnerabilityID, &f.DetectionSource, &f.DetectedAt,
		&f.LastConfirmedAt, &f.Status, &f.Confidence, &evidenceID,
	)
	if err != nil {
		return nil, err
	}
	f.EvidenceID = fromNullString(evidenceID)
	return &f, nil
}

// FindByID returns the Finding with the given id, or (nil, nil) if none
// exists.
func (r *FindingRepository) FindByID(ctx context.Context, id finding.ID) (*finding.Finding, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM findings WHERE id = $1`, id)
	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find finding %s: %w", id, err)
	}
	return f, nil
}

// FindByAssetAndVulnerability returns the Finding matching (assetID,
// vulnID), or (nil, nil) if none exists. This is CorrelateFindings's
// idempotency key (AGENTS.md §37).
func (r *FindingRepository) FindByAssetAndVulnerability(ctx context.Context, assetID asset.ID, vulnID vulnerability.ID) (*finding.Finding, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+findingColumns+` FROM findings
		WHERE asset_id = $1 AND vulnerability_id = $2
	`, assetID, vulnID)

	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find finding by asset and vulnerability: %w", err)
	}
	return f, nil
}

// List returns every Finding, most recently detected first.
func (r *FindingRepository) List(ctx context.Context) ([]*finding.Finding, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+findingColumns+` FROM findings ORDER BY detected_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list findings: %w", err)
	}
	defer rows.Close()

	var out []*finding.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan finding: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list findings: %w", err)
	}
	return out, nil
}
