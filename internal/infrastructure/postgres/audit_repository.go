package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/audit"
)

// AuditRepository implements application.AuditRepository against
// PostgreSQL.
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository returns an AuditRepository backed by db.
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Save inserts e. There is deliberately no update method on this type: an
// audit trail that could be edited after the fact would defeat its
// purpose (AGENTS.md §30).
func (r *AuditRepository) Save(ctx context.Context, e *audit.Entry) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_log (id, action, who, subject_type, subject_id, what, why, before, after, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, e.ID, e.Action, e.Who, e.SubjectType, e.SubjectID, e.What, e.Why, e.Before, e.After, e.OccurredAt)
	if err != nil {
		return fmt.Errorf("postgres: save audit entry %s: %w", e.ID, err)
	}
	return nil
}
