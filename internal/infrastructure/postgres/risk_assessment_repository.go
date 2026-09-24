package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/risk"
)

// RiskAssessmentRepository implements application.RiskAssessmentRepository
// against PostgreSQL.
type RiskAssessmentRepository struct {
	db *sql.DB
}

// NewRiskAssessmentRepository returns a RiskAssessmentRepository backed by
// db.
func NewRiskAssessmentRepository(db *sql.DB) *RiskAssessmentRepository {
	return &RiskAssessmentRepository{db: db}
}

// Save inserts a. RiskAssessments are append-only: a new assessment is a
// new row, never an update to a prior one, so history is preserved for
// FindLatestByFinding.
func (r *RiskAssessmentRepository) Save(ctx context.Context, a *risk.Assessment) error {
	factors, err := json.Marshal(a.Factors)
	if err != nil {
		return fmt.Errorf("postgres: marshal risk assessment factors: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO risk_assessments
			(id, finding_id, score, level, factors, policy_name, policy_version, assessed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, a.ID, a.FindingID, a.Score, a.Level, factors, a.PolicyName, a.PolicyVersion, a.AssessedAt)
	if err != nil {
		return fmt.Errorf("postgres: save risk assessment %s: %w", a.ID, err)
	}
	return nil
}

// FindLatestByFinding returns the most recently assessed RiskAssessment
// for findingID, or (nil, nil) if none exists.
func (r *RiskAssessmentRepository) FindLatestByFinding(ctx context.Context, findingID finding.ID) (*risk.Assessment, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, finding_id, score, level, factors, policy_name, policy_version, assessed_at
		FROM risk_assessments
		WHERE finding_id = $1
		ORDER BY assessed_at DESC
		LIMIT 1
	`, findingID)

	var a risk.Assessment
	var factors []byte
	err := row.Scan(&a.ID, &a.FindingID, &a.Score, &a.Level, &factors, &a.PolicyName, &a.PolicyVersion, &a.AssessedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find latest risk assessment for finding %s: %w", findingID, err)
	}
	if err := json.Unmarshal(factors, &a.Factors); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal risk assessment factors: %w", err)
	}
	return &a, nil
}
