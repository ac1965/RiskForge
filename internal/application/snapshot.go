package application

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

// toJSON renders v as a JSON snapshot for an audit.Entry's Before/After
// field. Domain types stay free of serialization concerns (AGENTS.md
// §25); producing this snapshot is Application's job.
func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}

// applyFindingStatus loads the Finding identified by id, transitions it to
// status if apply is true, and saves it. It is a no-op when apply is
// false, which is how an inconclusive Verification (AGENTS.md §20A.6.1)
// or a rejected Exception request correctly produces no Finding change.
func (s *Service) applyFindingStatus(ctx context.Context, id finding.ID, status finding.Status, apply bool) error {
	if !apply {
		return nil
	}

	f, err := s.Findings.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("application: load finding %s: %w", id, err)
	}
	if f == nil {
		return fmt.Errorf("application: finding %s not found", id)
	}
	if err := f.TransitionTo(status); err != nil {
		return fmt.Errorf("application: transition finding %s: %w", id, err)
	}
	if err := s.Findings.Save(ctx, f); err != nil {
		return fmt.Errorf("application: save finding %s: %w", id, err)
	}
	return nil
}
