package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
)

// PriorityDecisionRepository implements
// application.PriorityDecisionRepository against PostgreSQL.
type PriorityDecisionRepository struct {
	db *sql.DB
}

// NewPriorityDecisionRepository returns a PriorityDecisionRepository
// backed by db.
func NewPriorityDecisionRepository(db *sql.DB) *PriorityDecisionRepository {
	return &PriorityDecisionRepository{db: db}
}

// Save inserts d. Like risk_assessments, priority_decisions is
// append-only: a new decision is a new row.
func (r *PriorityDecisionRepository) Save(ctx context.Context, d *priority.Decision) error {
	factors, err := json.Marshal(d.Factors)
	if err != nil {
		return fmt.Errorf("postgres: marshal priority decision factors: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO priority_decisions
			(id, finding_id, risk_assessment_id, rank, level, factors, sla_deadline, policy_name, policy_version, decided_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, d.ID, d.FindingID, d.RiskAssessmentID, d.Rank, d.Level, factors, d.SLADeadline, d.PolicyName, d.PolicyVersion, d.DecidedAt)
	if err != nil {
		return fmt.Errorf("postgres: save priority decision %s: %w", d.ID, err)
	}
	return nil
}

const priorityDecisionColumns = `
	id, finding_id, risk_assessment_id, rank, level, factors,
	sla_deadline, policy_name, policy_version, decided_at`

func scanPriorityDecision(row rowScanner) (*priority.Decision, error) {
	var d priority.Decision
	var factors []byte
	err := row.Scan(&d.ID, &d.FindingID, &d.RiskAssessmentID, &d.Rank, &d.Level, &factors, &d.SLADeadline, &d.PolicyName, &d.PolicyVersion, &d.DecidedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(factors, &d.Factors); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal priority decision factors: %w", err)
	}
	return &d, nil
}

// FindLatestByFinding returns the most recently decided PriorityDecision
// for findingID, or (nil, nil) if none exists.
func (r *PriorityDecisionRepository) FindLatestByFinding(ctx context.Context, findingID finding.ID) (*priority.Decision, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+priorityDecisionColumns+`
		FROM priority_decisions
		WHERE finding_id = $1
		ORDER BY decided_at DESC
		LIMIT 1
	`, findingID)

	d, err := scanPriorityDecision(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find latest priority decision for finding %s: %w", findingID, err)
	}
	return d, nil
}

// ListLatest returns the most recently decided PriorityDecision for every
// Finding that has one.
func (r *PriorityDecisionRepository) ListLatest(ctx context.Context) ([]*priority.Decision, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (finding_id) `+priorityDecisionColumns+`
		FROM priority_decisions
		ORDER BY finding_id, decided_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list latest priority decisions: %w", err)
	}
	defer rows.Close()

	var out []*priority.Decision
	for rows.Next() {
		d, err := scanPriorityDecision(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan priority decision: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list latest priority decisions: %w", err)
	}
	return out, nil
}
