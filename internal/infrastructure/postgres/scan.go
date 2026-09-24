package postgres

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// rowScanner is satisfied by both *sql.Row and *sql.Rows, letting scan
// helpers work with either.
type rowScanner interface {
	Scan(dest ...any) error
}

// jsonStrings marshals a []string for storage in a JSONB column.
func jsonStrings(v []string) ([]byte, error) {
	if v == nil {
		v = []string{}
	}
	return json.Marshal(v)
}

// scanStrings unmarshals a JSONB column back into a []string.
func scanStrings(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal string array: %w", err)
	}
	return v, nil
}

// nullTime converts a possibly-zero time.Time into a sql.NullTime for
// storage in a nullable TIMESTAMPTZ column.
func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t, Valid: true}
}

// fromNullTime is the inverse of nullTime: a NULL column becomes a
// zero-value time.Time.
func fromNullTime(t sql.NullTime) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

// nullFloat converts a *float64 into a sql.NullFloat64.
func nullFloat(f *float64) sql.NullFloat64 {
	if f == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *f, Valid: true}
}

// fromNullFloat is the inverse of nullFloat.
func fromNullFloat(f sql.NullFloat64) *float64 {
	if !f.Valid {
		return nil
	}
	v := f.Float64
	return &v
}

// nullString converts an empty string into SQL NULL, for optional ID
// reference columns (e.g. findings.evidence_id's underlying string form)
// where empty-string and "no value" must be distinguished from a real,
// non-empty identifier.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// fromNullString is the inverse of nullString.
func fromNullString(s sql.NullString) string {
	if !s.Valid {
		return ""
	}
	return s.String
}
