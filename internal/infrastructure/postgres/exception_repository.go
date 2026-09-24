package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/exception"
)

// ExceptionRepository implements application.ExceptionRepository against
// PostgreSQL.
type ExceptionRepository struct {
	db *sql.DB
}

// NewExceptionRepository returns an ExceptionRepository backed by db.
func NewExceptionRepository(db *sql.DB) *ExceptionRepository {
	return &ExceptionRepository{db: db}
}

const exceptionColumns = `
	id, finding_id, reason, requested_by, approved_by, created_at,
	expires_at, compensating_control, status`

// Save inserts e, or updates it in place if e.ID already exists.
func (r *ExceptionRepository) Save(ctx context.Context, e *exception.Exception) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO exceptions (`+exceptionColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			finding_id = EXCLUDED.finding_id,
			reason = EXCLUDED.reason,
			requested_by = EXCLUDED.requested_by,
			approved_by = EXCLUDED.approved_by,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at,
			compensating_control = EXCLUDED.compensating_control,
			status = EXCLUDED.status
	`,
		e.ID, e.FindingID, e.Reason, e.RequestedBy, e.ApprovedBy,
		e.CreatedAt, e.ExpiresAt, e.CompensatingControl, e.Status,
	)
	if err != nil {
		return fmt.Errorf("postgres: save exception %s: %w", e.ID, err)
	}
	return nil
}

func scanException(row rowScanner) (*exception.Exception, error) {
	var e exception.Exception
	err := row.Scan(
		&e.ID, &e.FindingID, &e.Reason, &e.RequestedBy, &e.ApprovedBy,
		&e.CreatedAt, &e.ExpiresAt, &e.CompensatingControl, &e.Status,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// FindByID returns the Exception with the given id, or (nil, nil) if none
// exists.
func (r *ExceptionRepository) FindByID(ctx context.Context, id exception.ID) (*exception.Exception, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+exceptionColumns+` FROM exceptions WHERE id = $1`, id)
	e, err := scanException(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find exception %s: %w", id, err)
	}
	return e, nil
}

// List returns every Exception, most recently created first.
func (r *ExceptionRepository) List(ctx context.Context) ([]*exception.Exception, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+exceptionColumns+` FROM exceptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list exceptions: %w", err)
	}
	defer rows.Close()

	var out []*exception.Exception
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan exception: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list exceptions: %w", err)
	}
	return out, nil
}
