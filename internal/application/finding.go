package application

import (
	"context"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

// CorrelateFindings is the correlate_findings() Named API (AGENTS.md
// §26). It upserts by (AssetID, VulnerabilityID) (see
// FindingRepository.FindByAssetAndVulnerability): re-detecting the same
// vulnerability on the same asset confirms the existing Finding instead
// of creating a duplicate, per the idempotency requirement in AGENTS.md
// §37.
//
// This is a simplified stand-in for the full Scanner pipeline in AGENTS.md
// §20 (RawFinding -> Normalizer -> Matcher -> Finding); Asset and
// Vulnerability are assumed already correlated by the caller.
func (s *Service) CorrelateFindings(ctx context.Context, p finding.Params) (*finding.Finding, error) {
	a, err := s.Assets.FindByID(ctx, p.AssetID)
	if err != nil {
		return nil, fmt.Errorf("application: find asset %s: %w", p.AssetID, err)
	}
	if a == nil {
		return nil, fmt.Errorf("application: asset %s not found", p.AssetID)
	}

	v, err := s.Vulnerabilities.FindByID(ctx, p.VulnerabilityID)
	if err != nil {
		return nil, fmt.Errorf("application: find vulnerability %s: %w", p.VulnerabilityID, err)
	}
	if v == nil {
		return nil, fmt.Errorf("application: vulnerability %s not found", p.VulnerabilityID)
	}

	existing, err := s.Findings.FindByAssetAndVulnerability(ctx, p.AssetID, p.VulnerabilityID)
	if err != nil {
		return nil, fmt.Errorf("application: find finding by asset and vulnerability: %w", err)
	}

	if existing != nil {
		if err := existing.Confirm(p.DetectedAt); err != nil {
			return nil, fmt.Errorf("application: confirm finding %s: %w", existing.ID, err)
		}
		if err := s.Findings.Save(ctx, existing); err != nil {
			return nil, fmt.Errorf("application: save finding %s: %w", existing.ID, err)
		}
		return existing, nil
	}

	f, err := finding.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: create finding: %w", err)
	}
	if err := s.Findings.Save(ctx, f); err != nil {
		return nil, fmt.Errorf("application: save finding %s: %w", f.ID, err)
	}
	return f, nil
}
