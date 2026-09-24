package priority

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/risk"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

type staticRemediationProvider struct{ available bool }

func (p staticRemediationProvider) RemediationAvailability(Input) (bool, error) {
	return p.available, nil
}

func newTestEngine(t *testing.T, remediationAvailable bool, constraints BusinessConstraints) *Engine {
	t.Helper()
	e, err := NewEngine(
		risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{},
		risk.FromAssetProvider{},
		staticRemediationProvider{available: remediationAvailable},
		StaticBusinessConstraintsProvider{Constraints: constraints},
		BaselinePolicy{},
		NewDefaultSLAPolicy(),
	)
	if err != nil {
		t.Fatalf("NewEngine() unexpected error: %v", err)
	}
	return e
}

func TestNewEngineRequiresAllDependencies(t *testing.T) {
	ep := risk.FromVulnerabilityProvider{}
	ap := risk.FromAssetProvider{}
	rp := staticRemediationProvider{}
	bc := StaticBusinessConstraintsProvider{}
	policy := BaselinePolicy{}
	sla := NewDefaultSLAPolicy()

	if _, err := NewEngine(nil, ap, ap, rp, bc, policy, sla); err == nil {
		t.Error("NewEngine() with nil exploitability provider: want error, got nil")
	}
	if _, err := NewEngine(ep, nil, ap, rp, bc, policy, sla); err == nil {
		t.Error("NewEngine() with nil asset criticality provider: want error, got nil")
	}
	if _, err := NewEngine(ep, ap, nil, rp, bc, policy, sla); err == nil {
		t.Error("NewEngine() with nil exposure provider: want error, got nil")
	}
	if _, err := NewEngine(ep, ap, ap, nil, bc, policy, sla); err == nil {
		t.Error("NewEngine() with nil remediation availability provider: want error, got nil")
	}
	if _, err := NewEngine(ep, ap, ap, rp, nil, policy, sla); err == nil {
		t.Error("NewEngine() with nil business constraints provider: want error, got nil")
	}
	if _, err := NewEngine(ep, ap, ap, rp, bc, nil, sla); err == nil {
		t.Error("NewEngine() with nil policy: want error, got nil")
	}
	if _, err := NewEngine(ep, ap, ap, rp, bc, policy, nil); err == nil {
		t.Error("NewEngine() with nil sla policy: want error, got nil")
	}
}

func testAssetParams(criticality asset.Criticality, exposure asset.Exposure, env asset.Environment) asset.Params {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return asset.Params{
		Hostname:       "host-01",
		Type:           asset.TypeServer,
		Environment:    env,
		Criticality:    criticality,
		Exposure:       exposure,
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: asset.LifecycleActive,
	}
}

func testVulnerabilityParams() vulnerability.Params {
	return vulnerability.Params{
		CVEID:       "CVE-2026-00003",
		Title:       "Test vulnerability",
		Severity:    vulnerability.SeverityHigh,
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// buildInput constructs a self-consistent priority.Input, with a
// risk.Assessment carrying the given score/level for a fresh Asset,
// Vulnerability, and Finding.
func buildInput(t *testing.T, assetParams asset.Params, riskScore float64, riskLevel risk.Level) Input {
	t.Helper()

	a, err := asset.New(assetParams)
	if err != nil {
		t.Fatalf("asset.New() unexpected error: %v", err)
	}
	v, err := vulnerability.New(testVulnerabilityParams())
	if err != nil {
		t.Fatalf("vulnerability.New() unexpected error: %v", err)
	}
	f, err := finding.New(finding.Params{
		AssetID:         a.ID,
		VulnerabilityID: v.ID,
		DetectionSource: "test-scanner",
		DetectedAt:      time.Now(),
		Confidence:      finding.ConfidenceConfirmed,
	})
	if err != nil {
		t.Fatalf("finding.New() unexpected error: %v", err)
	}
	ra, err := risk.New(risk.Params{
		FindingID:     f.ID,
		Score:         riskScore,
		Level:         riskLevel,
		Factors:       []explainability.Factor{{Name: "test", Value: "test", Reason: "fixed for this test"}},
		PolicyName:    "test-fixture",
		PolicyVersion: "0",
		AssessedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("risk.New() unexpected error: %v", err)
	}

	return Input{
		Input:          risk.Input{Finding: f, Asset: a, Vulnerability: v},
		RiskAssessment: ra,
	}
}

func TestEngineDecideRejectsMismatchedInput(t *testing.T) {
	e := newTestEngine(t, true, BusinessConstraints{})
	in := buildInput(t, testAssetParams(asset.CriticalityCritical, asset.Exposure{Level: asset.LevelDirect, InternetExposed: true}, asset.EnvironmentProduction), 50, risk.LevelMedium)

	otherAsset, err := asset.New(testAssetParams(asset.CriticalityLow, asset.Exposure{Level: asset.LevelInternalOnly}, asset.EnvironmentDevelopment))
	if err != nil {
		t.Fatalf("asset.New() unexpected error: %v", err)
	}
	in.Asset = otherAsset

	if _, err := e.Decide(in); err == nil {
		t.Error("Decide() with mismatched asset id: want error, got nil")
	}
}

// TestSameRiskDifferentPriority is the AGENTS.md §12 / §44 Invariant 2
// scenario: two Findings with the identical Risk score are prioritized
// differently because one asset is critical, production, and
// internet-facing while the other is low-criticality and internal-only.
func TestSameRiskDifferentPriority(t *testing.T) {
	const sameScore = 50.0

	e := newTestEngine(t, true, BusinessConstraints{})

	criticalInput := buildInput(t, testAssetParams(
		asset.CriticalityCritical,
		asset.Exposure{Level: asset.LevelDirect, InternetExposed: true},
		asset.EnvironmentProduction,
	), sameScore, risk.LevelMedium)

	lowInput := buildInput(t, testAssetParams(
		asset.CriticalityLow,
		asset.Exposure{Level: asset.LevelInternalOnly},
		asset.EnvironmentDevelopment,
	), sameScore, risk.LevelMedium)

	criticalDecision, err := e.Decide(criticalInput)
	if err != nil {
		t.Fatalf("Decide(critical) unexpected error: %v", err)
	}
	lowDecision, err := e.Decide(lowInput)
	if err != nil {
		t.Fatalf("Decide(low) unexpected error: %v", err)
	}

	if criticalInput.RiskAssessment.Score != lowInput.RiskAssessment.Score {
		t.Fatalf("test setup invalid: risk scores differ (%v vs %v)", criticalInput.RiskAssessment.Score, lowInput.RiskAssessment.Score)
	}
	if criticalDecision.Rank <= lowDecision.Rank {
		t.Errorf("Rank for critical/exposed (%v) is not greater than for low/internal (%v) despite equal risk score", criticalDecision.Rank, lowDecision.Rank)
	}
	if len(criticalDecision.Factors) == 0 {
		t.Error("decision has no explaining factors (AGENTS.md §40)")
	}
}

func TestRemediationAvailabilityAffectsRank(t *testing.T) {
	assetParams := testAssetParams(asset.CriticalityMedium, asset.Exposure{Level: asset.LevelInternalOnly}, asset.EnvironmentProduction)

	withFix := newTestEngine(t, true, BusinessConstraints{})
	in1 := buildInput(t, assetParams, 50, risk.LevelMedium)
	d1, err := withFix.Decide(in1)
	if err != nil {
		t.Fatalf("Decide() unexpected error: %v", err)
	}

	withoutFix := newTestEngine(t, false, BusinessConstraints{})
	in2 := buildInput(t, assetParams, 50, risk.LevelMedium)
	d2, err := withoutFix.Decide(in2)
	if err != nil {
		t.Fatalf("Decide() unexpected error: %v", err)
	}

	if d1.Rank <= d2.Rank {
		t.Errorf("Rank with remediation available (%v) is not greater than without (%v)", d1.Rank, d2.Rank)
	}
}
