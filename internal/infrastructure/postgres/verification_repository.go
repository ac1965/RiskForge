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

// Save inserts v. Verifications are append-only: each recorded
// verification is a new row, never an update to a prior one.
func (r *VerificationRepository) Save(ctx context.Context, v *verification.Verification) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO verifications (id, finding_id, method, verified_at, result, evidence_id)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, v.ID, v.FindingID, v.Method, v.VerifiedAt, v.Result, v.EvidenceID)
	if err != nil {
		return fmt.Errorf("postgres: save verification %s: %w", v.ID, err)
	}
	return nil
}
