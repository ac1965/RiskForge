package application

import (
	"context"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/evidence"
)

// RecordEvidence is the record_evidence() Named API (AGENTS.md §26). It is
// not audited: evidence collection itself is not in AGENTS.md §30's list
// of audited actions (see docs/adr/0008-application-layer.md) — Evidence
// is already tamper-evident and immutable on its own (§17, §22, §47.10).
func (s *Service) RecordEvidence(ctx context.Context, p evidence.Params) (*evidence.Evidence, error) {
	a, err := s.Assets.FindByID(ctx, p.AssetID)
	if err != nil {
		return nil, fmt.Errorf("application: find asset %s: %w", p.AssetID, err)
	}
	if a == nil {
		return nil, fmt.Errorf("application: asset %s not found", p.AssetID)
	}

	e, err := evidence.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: record evidence: %w", err)
	}
	if err := s.Evidence.Save(ctx, e); err != nil {
		return nil, fmt.Errorf("application: save evidence %s: %w", e.ID, err)
	}
	return e, nil
}
