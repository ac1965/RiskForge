package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/remediation"
)

// RemediationPlanRepository implements
// application.RemediationPlanRepository against PostgreSQL.
type RemediationPlanRepository struct {
	db *sql.DB
}

// NewRemediationPlanRepository returns a RemediationPlanRepository backed
// by db.
func NewRemediationPlanRepository(db *sql.DB) *RemediationPlanRepository {
	return &RemediationPlanRepository{db: db}
}

const remediationPlanColumns = `
	id, finding_id, action_type, description, proposed_by, approved_by,
	scheduled_at, executed_at, status, rollback_capable, rollback_plan,
	rollback_reason`

// Save inserts p, or updates it in place if p.ID already exists.
func (r *RemediationPlanRepository) Save(ctx context.Context, p *remediation.Plan) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO remediation_plans (`+remediationPlanColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id) DO UPDATE SET
			finding_id = EXCLUDED.finding_id,
			action_type = EXCLUDED.action_type,
			description = EXCLUDED.description,
			proposed_by = EXCLUDED.proposed_by,
			approved_by = EXCLUDED.approved_by,
			scheduled_at = EXCLUDED.scheduled_at,
			executed_at = EXCLUDED.executed_at,
			status = EXCLUDED.status,
			rollback_capable = EXCLUDED.rollback_capable,
			rollback_plan = EXCLUDED.rollback_plan,
			rollback_reason = EXCLUDED.rollback_reason
	`,
		p.ID, p.FindingID, p.ActionType, p.Description, p.ProposedBy, p.ApprovedBy,
		nullTime(p.ScheduledAt), nullTime(p.ExecutedAt), p.Status,
		p.Rollback.Capable, p.Rollback.Plan, p.Rollback.Reason,
	)
	if err != nil {
		return fmt.Errorf("postgres: save remediation plan %s: %w", p.ID, err)
	}
	return nil
}

func scanRemediationPlan(row rowScanner) (*remediation.Plan, error) {
	var p remediation.Plan
	var scheduledAt, executedAt sql.NullTime

	err := row.Scan(
		&p.ID, &p.FindingID, &p.ActionType, &p.Description, &p.ProposedBy, &p.ApprovedBy,
		&scheduledAt, &executedAt, &p.Status,
		&p.Rollback.Capable, &p.Rollback.Plan, &p.Rollback.Reason,
	)
	if err != nil {
		return nil, err
	}
	p.ScheduledAt = fromNullTime(scheduledAt)
	p.ExecutedAt = fromNullTime(executedAt)
	return &p, nil
}

// FindByID returns the RemediationPlan with the given id, or (nil, nil) if
// none exists.
func (r *RemediationPlanRepository) FindByID(ctx context.Context, id remediation.ID) (*remediation.Plan, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+remediationPlanColumns+` FROM remediation_plans WHERE id = $1`, id)
	p, err := scanRemediationPlan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find remediation plan %s: %w", id, err)
	}
	return p, nil
}

// List returns every RemediationPlan, ordered by status then id (Plan has
// no creation timestamp of its own — see AGENTS.md §14's field list).
func (r *RemediationPlanRepository) List(ctx context.Context) ([]*remediation.Plan, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+remediationPlanColumns+` FROM remediation_plans ORDER BY status, id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list remediation plans: %w", err)
	}
	defer rows.Close()

	var out []*remediation.Plan
	for rows.Next() {
		p, err := scanRemediationPlan(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan remediation plan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list remediation plans: %w", err)
	}
	return out, nil
}
