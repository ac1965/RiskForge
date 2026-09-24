package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/software"
)

// DiscoverAssets is the discover_assets() Named API (AGENTS.md §26). It
// upserts by Hostname (see AssetRepository.FindByHostname): rediscovering
// an already-known host advances its LastSeen instead of creating a
// duplicate Asset, per the idempotency requirement in AGENTS.md §37.
func (s *Service) DiscoverAssets(ctx context.Context, p asset.Params, at time.Time) (*asset.Asset, error) {
	existing, err := s.Assets.FindByHostname(ctx, p.Hostname)
	if err != nil {
		return nil, fmt.Errorf("application: find asset by hostname %q: %w", p.Hostname, err)
	}

	if existing != nil {
		if err := existing.Observe(at); err != nil {
			return nil, fmt.Errorf("application: observe asset %s: %w", existing.ID, err)
		}
		if err := s.Assets.Save(ctx, existing); err != nil {
			return nil, fmt.Errorf("application: save asset %s: %w", existing.ID, err)
		}
		return existing, nil
	}

	a, err := asset.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: create asset: %w", err)
	}
	if err := s.Assets.Save(ctx, a); err != nil {
		return nil, fmt.Errorf("application: save asset %s: %w", a.ID, err)
	}
	return a, nil
}

// InventoryAsset is the inventory_asset() Named API (AGENTS.md §26). It
// upserts by (AssetID, Vendor, Product, Version) (see
// SoftwareRepository.FindByNaturalKey): re-observing the same package on
// the same asset advances LastSeen instead of creating a duplicate
// Installation, per AGENTS.md §37.
func (s *Service) InventoryAsset(ctx context.Context, p software.Params, at time.Time) (*software.Installation, error) {
	a, err := s.Assets.FindByID(ctx, p.AssetID)
	if err != nil {
		return nil, fmt.Errorf("application: find asset %s: %w", p.AssetID, err)
	}
	if a == nil {
		return nil, fmt.Errorf("application: asset %s not found", p.AssetID)
	}

	existing, err := s.Software.FindByNaturalKey(ctx, p.AssetID, p.Vendor, p.Product, p.Version)
	if err != nil {
		return nil, fmt.Errorf("application: find software installation: %w", err)
	}

	if existing != nil {
		if err := existing.Observe(at); err != nil {
			return nil, fmt.Errorf("application: observe software installation %s: %w", existing.ID, err)
		}
		if err := s.Software.Save(ctx, existing); err != nil {
			return nil, fmt.Errorf("application: save software installation %s: %w", existing.ID, err)
		}
		return existing, nil
	}

	inst, err := software.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: create software installation: %w", err)
	}
	if err := s.Software.Save(ctx, inst); err != nil {
		return nil, fmt.Errorf("application: save software installation %s: %w", inst.ID, err)
	}
	return inst, nil
}
