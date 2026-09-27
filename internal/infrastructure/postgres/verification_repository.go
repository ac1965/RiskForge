package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/verification"
)

// VerificationRepository implements application.VerificationRepository
// against PostgreSQL.
type VerificationRepository struct {
	db *sql.DB
}

// NewVerificationRepository returns a VerificationRepository backed by
// db.
func NewVerificationRepository(db *sql.DB) *VerificationRepository {
	return &VerificationRepository{db: db}
}

const verificationColumns = `id, finding_id, method, verified_at, result, evidence_id`

// Save inserts v. Verifications are append-only: each recorded
// verification is a new row, never an update to a prior one.
func (r *VerificationRepository) Save(ctx context.Context, v *verification.Verification) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO verifications (`+verificationColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, v.ID, v.FindingID, v.Method, v.VerifiedAt, v.Result, v.EvidenceID)
	if err != nil {
		return fmt.Errorf("postgres: save verification %s: %w", v.ID, err)
	}
	return nil
}

func scanVerification(row rowScanner) (*verification.Verification, error) {
	var v verification.Verification
	if err := row.Scan(&v.ID, &v.FindingID, &v.Method, &v.VerifiedAt, &v.Result, &v.EvidenceID); err != nil {
		return nil, err
	}
	return &v, nil
}

// List returns every Verification, most recently verified first.
func (r *VerificationRepository) List(ctx context.Context) ([]*verification.Verification, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+verificationColumns+` FROM verifications ORDER BY verified_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list verifications: %w", err)
	}
	defer rows.Close()

	var out []*verification.Verification
	for rows.Next() {
		v, err := scanVerification(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan verification: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list verifications: %w", err)
	}
	return out, nil
}
