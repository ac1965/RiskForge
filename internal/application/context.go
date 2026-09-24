package application

import (
	"context"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// loadFindingContext loads a Finding together with its Asset and
// Vulnerability, verifying the three are internally consistent (the same
// integrity check risk.Engine.Assess and priority.Engine.Decide perform
// on their own Input). It is shared by every Named API that needs a
// Finding's full context.
func (s *Service) loadFindingContext(ctx context.Context, findingID finding.ID) (*finding.Finding, *asset.Asset, *vulnerability.Vulnerability, error) {
	f, err := s.Findings.FindByID(ctx, findingID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("application: find finding %s: %w", findingID, err)
	}
	if f == nil {
		return nil, nil, nil, fmt.Errorf("application: finding %s not found", findingID)
	}

	a, err := s.Assets.FindByID(ctx, f.AssetID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("application: find asset %s: %w", f.AssetID, err)
	}
	if a == nil {
		return nil, nil, nil, fmt.Errorf("application: asset %s not found", f.AssetID)
	}

	v, err := s.Vulnerabilities.FindByID(ctx, f.VulnerabilityID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("application: find vulnerability %s: %w", f.VulnerabilityID, err)
	}
	if v == nil {
		return nil, nil, nil, fmt.Errorf("application: vulnerability %s not found", f.VulnerabilityID)
	}

	return f, a, v, nil
}
