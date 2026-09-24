package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/software"
)

func testAssetParams() asset.Params {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return asset.Params{
		Hostname:       "web-01",
		Type:           asset.TypeServer,
		Environment:    asset.EnvironmentProduction,
		Criticality:    asset.CriticalityHigh,
		Exposure:       asset.Exposure{Level: asset.LevelDirect, InternetExposed: true},
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: asset.LifecycleActive,
	}
}

// TestDiscoverAssetsIdempotent is the AGENTS.md §37 scenario: discovering
// the same host twice must not create two Asset records.
func TestDiscoverAssetsIdempotent(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	p := testAssetParams()

	first, err := svc.DiscoverAssets(ctx, p, p.FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}

	second, err := svc.DiscoverAssets(ctx, p, p.FirstSeen.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("DiscoverAssets() second call unexpected error: %v", err)
	}

	if first.ID != second.ID {
		t.Errorf("second DiscoverAssets() created a new asset: %s != %s", first.ID, second.ID)
	}
	if len(repos.assets.byID) != 1 {
		t.Errorf("asset repository has %d records, want 1", len(repos.assets.byID))
	}
	if !second.LastSeen.Equal(p.FirstSeen.Add(24 * time.Hour)) {
		t.Errorf("LastSeen = %s, want advanced timestamp", second.LastSeen)
	}
}

// TestInventoryAssetIdempotent is the AGENTS.md §37 scenario for software
// inventory: observing the same package twice on the same asset must not
// create two Installation records.
func TestInventoryAssetIdempotent(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()

	a, err := svc.DiscoverAssets(ctx, testAssetParams(), testAssetParams().FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}

	swParams := software.Params{
		AssetID:   a.ID,
		Vendor:    "openssl",
		Product:   "openssl",
		Version:   "3.0.13",
		FirstSeen: a.FirstSeen,
		LastSeen:  a.FirstSeen,
	}

	first, err := svc.InventoryAsset(ctx, swParams, swParams.FirstSeen)
	if err != nil {
		t.Fatalf("InventoryAsset() unexpected error: %v", err)
	}
	second, err := svc.InventoryAsset(ctx, swParams, swParams.FirstSeen.Add(time.Hour))
	if err != nil {
		t.Fatalf("InventoryAsset() second call unexpected error: %v", err)
	}

	if first.ID != second.ID {
		t.Errorf("second InventoryAsset() created a new installation: %s != %s", first.ID, second.ID)
	}
	if len(repos.software.byID) != 1 {
		t.Errorf("software repository has %d records, want 1", len(repos.software.byID))
	}
}

func TestInventoryAssetRequiresExistingAsset(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.InventoryAsset(ctx, software.Params{
		AssetID:   asset.NewID(),
		Vendor:    "openssl",
		Product:   "openssl",
		Version:   "3.0.13",
		FirstSeen: time.Now(),
	}, time.Now())
	if err == nil {
		t.Error("InventoryAsset() with unknown asset id: want error, got nil")
	}
}
