package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
)

func TestRecordEvidence(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.DiscoverAssets(ctx, testAssetParams(), testAssetParams().FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}

	content := []byte("raw scan output")
	e, err := svc.RecordEvidence(ctx, evidence.Params{
		Type:        evidence.TypeDetectionResult,
		Source:      "nessus",
		CollectedAt: time.Now(),
		AssetID:     a.ID,
		ContentHash: evidence.ComputeContentHash(content),
		Location:    "s3://evidence/scan-1.json",
	})
	if err != nil {
		t.Fatalf("RecordEvidence() unexpected error: %v", err)
	}
	if e.ID == "" {
		t.Error("RecordEvidence() did not assign an ID")
	}
}

func TestRecordEvidenceRequiresExistingAsset(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.RecordEvidence(ctx, evidence.Params{
		Type:        evidence.TypeDetectionResult,
		Source:      "nessus",
		CollectedAt: time.Now(),
		AssetID:     asset.NewID(),
		ContentHash: evidence.ComputeContentHash([]byte("x")),
		Location:    "s3://evidence/scan-2.json",
	})
	if err == nil {
		t.Error("RecordEvidence() with unknown asset id: want error, got nil")
	}
}
