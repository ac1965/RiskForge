package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// RawFindingRepository implements application.RawFindingRepository against
// PostgreSQL.
type RawFindingRepository struct {
	db *sql.DB
}

// NewRawFindingRepository returns a RawFindingRepository backed by db.
func NewRawFindingRepository(db *sql.DB) *RawFindingRepository {
	return &RawFindingRepository{db: db}
}

const rawFindingColumns = `
	id, source, source_ref, asset_id, evidence_id, title, detail, confidence,
	cvss_v3, cvss_vector, native_severity, attack_technique_ids, collected_at`

// Save inserts rf, or updates it in place if rf.ID already exists (mirrors
// vulnerability_repository.go's upsert style -- unlike Evidence,
// RawFinding has no immutability requirement in AGENTS.md §20A).
func (r *RawFindingRepository) Save(ctx context.Context, rf *rawfinding.RawFinding) error {
	attackTechniqueIDs, err := jsonStrings(rf.AttackTechniqueIDs)
	if err != nil {
		return fmt.Errorf("postgres: marshal attack technique ids: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO raw_findings (`+rawFindingColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (id) DO UPDATE SET
			source = EXCLUDED.source,
			source_ref = EXCLUDED.source_ref,
			asset_id = EXCLUDED.asset_id,
			evidence_id = EXCLUDED.evidence_id,
			title = EXCLUDED.title,
			detail = EXCLUDED.detail,
			confidence = EXCLUDED.confidence,
			cvss_v3 = EXCLUDED.cvss_v3,
			cvss_vector = EXCLUDED.cvss_vector,
			native_severity = EXCLUDED.native_severity,
			attack_technique_ids = EXCLUDED.attack_technique_ids,
			collected_at = EXCLUDED.collected_at
	`,
		rf.ID, rf.Source, rf.SourceRef, rf.AssetID, nullString(string(rf.EvidenceID)),
		rf.Title, rf.Detail, rf.Confidence, nullFloat(rf.CVSSScore), rf.CVSSVector,
		rf.NativeSeverity, attackTechniqueIDs, rf.CollectedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: save rawfinding %s: %w", rf.ID, err)
	}
	return nil
}

func scanRawFinding(row rowScanner) (*rawfinding.RawFinding, error) {
	var rf rawfinding.RawFinding
	var evidenceID sql.NullString
	var cvssV3 sql.NullFloat64
	var attackTechniqueIDs []byte

	err := row.Scan(
		&rf.ID, &rf.Source, &rf.SourceRef, &rf.AssetID, &evidenceID,
		&rf.Title, &rf.Detail, &rf.Confidence, &cvssV3, &rf.CVSSVector,
		&rf.NativeSeverity, &attackTechniqueIDs, &rf.CollectedAt,
	)
	if err != nil {
		return nil, err
	}

	rf.EvidenceID = evidence.ID(fromNullString(evidenceID))
	rf.CVSSScore = fromNullFloat(cvssV3)
	if rf.AttackTechniqueIDs, err = scanStrings(attackTechniqueIDs); err != nil {
		return nil, err
	}
	return &rf, nil
}

// FindByID returns the RawFinding with the given id, or (nil, nil) if none
// exists.
func (r *RawFindingRepository) FindByID(ctx context.Context, id rawfinding.ID) (*rawfinding.RawFinding, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+rawFindingColumns+` FROM raw_findings WHERE id = $1`, id)
	rf, err := scanRawFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find rawfinding %s: %w", id, err)
	}
	return rf, nil
}

// List returns every held RawFinding, most recently collected first.
func (r *RawFindingRepository) List(ctx context.Context) ([]*rawfinding.RawFinding, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+rawFindingColumns+` FROM raw_findings ORDER BY collected_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list rawfindings: %w", err)
	}
	defer rows.Close()

	var out []*rawfinding.RawFinding
	for rows.Next() {
		rf, err := scanRawFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan rawfinding: %w", err)
		}
		out = append(out, rf)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list rawfindings: %w", err)
	}
	return out, nil
}
