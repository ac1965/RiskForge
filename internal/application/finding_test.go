package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

func seedAssetAndVulnerability(t *testing.T, svc *Service, repos *testRepos) (asset.ID, vulnerability.ID) {
	t.Helper()
	ctx := context.Background()

	a, err := svc.DiscoverAssets(ctx, testAssetParams(), testAssetParams().FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}

	v, err := vulnerability.New(vulnerability.Params{
		Title:       "Test vulnerability",
		Severity:    vulnerability.SeverityHigh,
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("vulnerability.New() unexpected error: %v", err)
	}
	if err := repos.vulnerabilities.Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}

	return a.ID, v.ID
}

// TestCorrelateFindingsIdempotent is the AGENTS.md §37 scenario: repeated
// detection of the same vulnerability on the same asset must confirm the
// existing Finding, not create a duplicate.
func TestCorrelateFindingsIdempotent(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	assetID, vulnID := seedAssetAndVulnerability(t, svc, repos)

	detectedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := finding.Params{
		AssetID:         assetID,
		VulnerabilityID: vulnID,
		DetectionSource: "test-scanner",
		DetectedAt:      detectedAt,
		Confidence:      finding.ConfidenceHigh,
	}

	first, err := svc.CorrelateFindings(ctx, p)
	if err != nil {
		t.Fatalf("CorrelateFindings() unexpected error: %v", err)
	}

	p.DetectedAt = detectedAt.Add(48 * time.Hour)
	second, err := svc.CorrelateFindings(ctx, p)
	if err != nil {
		t.Fatalf("CorrelateFindings() second call unexpected error: %v", err)
	}

	if first.ID != second.ID {
		t.Errorf("second CorrelateFindings() created a new finding: %s != %s", first.ID, second.ID)
	}
	if len(repos.findings.byID) != 1 {
		t.Errorf("finding repository has %d records, want 1", len(repos.findings.byID))
	}
	if !second.LastConfirmedAt.Equal(detectedAt.Add(48 * time.Hour)) {
		t.Errorf("LastConfirmedAt = %s, want advanced timestamp", second.LastConfirmedAt)
	}
}

func TestCorrelateFindingsRequiresExistingAssetAndVulnerability(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()
	assetID, vulnID := seedAssetAndVulnerability(t, svc, repos)

	_, err := svc.CorrelateFindings(ctx, finding.Params{
		AssetID:         "does-not-exist",
		VulnerabilityID: vulnID,
		DetectionSource: "test-scanner",
		DetectedAt:      time.Now(),
		Confidence:      finding.ConfidenceHigh,
	})
	if err == nil {
		t.Error("CorrelateFindings() with unknown asset id: want error, got nil")
	}

	_, err = svc.CorrelateFindings(ctx, finding.Params{
		AssetID:         assetID,
		VulnerabilityID: "does-not-exist",
		DetectionSource: "test-scanner",
		DetectedAt:      time.Now(),
		Confidence:      finding.ConfidenceHigh,
	})
	if err == nil {
		t.Error("CorrelateFindings() with unknown vulnerability id: want error, got nil")
	}
}
