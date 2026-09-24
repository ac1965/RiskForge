package remediation

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

func buildDryRunInput(t *testing.T) (DryRunInput, *Plan) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	a, err := asset.New(asset.Params{
		Hostname:       "web-01",
		Type:           asset.TypeServer,
		Environment:    asset.EnvironmentProduction,
		Criticality:    asset.CriticalityHigh,
		Exposure:       asset.Exposure{Level: asset.LevelInternalOnly},
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: asset.LifecycleActive,
	})
	if err != nil {
		t.Fatalf("asset.New() unexpected error: %v", err)
	}

	v, err := vulnerability.New(vulnerability.Params{
		Title:       "Test vulnerability",
		Severity:    vulnerability.SeverityHigh,
		PublishedAt: now,
	})
	if err != nil {
		t.Fatalf("vulnerability.New() unexpected error: %v", err)
	}

	f, err := finding.New(finding.Params{
		AssetID:         a.ID,
		VulnerabilityID: v.ID,
		DetectionSource: "test-scanner",
		DetectedAt:      now,
		Confidence:      finding.ConfidenceConfirmed,
	})
	if err != nil {
		t.Fatalf("finding.New() unexpected error: %v", err)
	}

	p := validParams()
	p.FindingID = f.ID
	plan, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	return DryRunInput{Finding: f, Asset: a}, plan
}

func TestPlanDryRun(t *testing.T) {
	in, plan := buildDryRunInput(t)

	report, err := plan.DryRun(in, "openssl 3.0.13 -> 3.0.14")
	if err != nil {
		t.Fatalf("DryRun() unexpected error: %v", err)
	}
	if report.AssetID != in.Asset.ID {
		t.Errorf("AssetID = %q, want %q", report.AssetID, in.Asset.ID)
	}
	if report.FindingID != plan.FindingID {
		t.Errorf("FindingID = %q, want %q", report.FindingID, plan.FindingID)
	}
	if report.Target == "" {
		t.Error("DryRun() report has no target")
	}
	if report.Rollback != plan.Rollback {
		t.Errorf("Rollback = %+v, want %+v", report.Rollback, plan.Rollback)
	}
}

func TestPlanDryRunRejectsMismatchedFinding(t *testing.T) {
	in, plan := buildDryRunInput(t)

	otherFinding, err := finding.New(finding.Params{
		AssetID:         in.Asset.ID,
		VulnerabilityID: in.Finding.VulnerabilityID,
		DetectionSource: "test-scanner",
		DetectedAt:      time.Now(),
		Confidence:      finding.ConfidenceConfirmed,
	})
	if err != nil {
		t.Fatalf("finding.New() unexpected error: %v", err)
	}
	in.Finding = otherFinding

	if _, err := plan.DryRun(in, "target"); err == nil {
		t.Error("DryRun() with mismatched finding id: want error, got nil")
	}
}
