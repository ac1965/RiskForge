package risk

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

func newTestEngine(t *testing.T, businessImpact BusinessImpact) *Engine {
	t.Helper()
	e, err := NewEngine(
		FromVulnerabilityProvider{},
		FromVulnerabilityProvider{},
		FromAssetProvider{},
		FromAssetProvider{},
		StaticBusinessImpactProvider{Impact: businessImpact},
		BaselinePolicy{},
	)
	if err != nil {
		t.Fatalf("NewEngine() unexpected error: %v", err)
	}
	return e
}

func TestNewEngineRequiresAllDependencies(t *testing.T) {
	p := FromVulnerabilityProvider{}
	a := FromAssetProvider{}
	bi := StaticBusinessImpactProvider{}
	policy := BaselinePolicy{}

	if _, err := NewEngine(nil, p, a, a, bi, policy); err == nil {
		t.Error("NewEngine() with nil severity provider: want error, got nil")
	}
	if _, err := NewEngine(p, nil, a, a, bi, policy); err == nil {
		t.Error("NewEngine() with nil exploitability provider: want error, got nil")
	}
	if _, err := NewEngine(p, p, nil, a, bi, policy); err == nil {
		t.Error("NewEngine() with nil asset criticality provider: want error, got nil")
	}
	if _, err := NewEngine(p, p, a, nil, bi, policy); err == nil {
		t.Error("NewEngine() with nil exposure provider: want error, got nil")
	}
	if _, err := NewEngine(p, p, a, a, nil, policy); err == nil {
		t.Error("NewEngine() with nil business impact provider: want error, got nil")
	}
	if _, err := NewEngine(p, p, a, a, bi, nil); err == nil {
		t.Error("NewEngine() with nil policy: want error, got nil")
	}
}

// buildInput constructs a self-consistent risk.Input from fresh Asset,
// Vulnerability, and Finding entities.
func buildInput(t *testing.T, assetParams asset.Params, vulnParams vulnerability.Params) Input {
	t.Helper()

	a, err := asset.New(assetParams)
	if err != nil {
		t.Fatalf("asset.New() unexpected error: %v", err)
	}
	v, err := vulnerability.New(vulnParams)
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

	return Input{Finding: f, Asset: a, Vulnerability: v}
}

func TestEngineAssessRejectsMismatchedInput(t *testing.T) {
	e := newTestEngine(t, BusinessImpact{})
	in := buildInput(t, criticalExposedAssetParams(), kevVulnerabilityParams())

	otherAsset, err := asset.New(criticalExposedAssetParams())
	if err != nil {
		t.Fatalf("asset.New() unexpected error: %v", err)
	}
	in.Asset = otherAsset

	if _, err := e.Assess(in); err == nil {
		t.Error("Assess() with mismatched asset id: want error, got nil")
	}
}

func now() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func criticalExposedAssetParams() asset.Params {
	return asset.Params{
		Hostname:       "prod-web-01",
		Type:           asset.TypeServer,
		Environment:    asset.EnvironmentProduction,
		Criticality:    asset.CriticalityCritical,
		Exposure:       asset.Exposure{Level: asset.LevelDirect, InternetExposed: true},
		FirstSeen:      now(),
		LastSeen:       now(),
		LifecycleState: asset.LifecycleActive,
	}
}

func lowInternalAssetParams() asset.Params {
	return asset.Params{
		Hostname:       "dev-box-01",
		Type:           asset.TypeWorkstation,
		Environment:    asset.EnvironmentDevelopment,
		Criticality:    asset.CriticalityLow,
		Exposure:       asset.Exposure{Level: asset.LevelInternalOnly},
		FirstSeen:      now(),
		LastSeen:       now(),
		LifecycleState: asset.LifecycleActive,
	}
}

func kevVulnerabilityParams() vulnerability.Params {
	return vulnerability.Params{
		CVEID:                "CVE-2026-00001",
		Title:                "Known exploited RCE",
		Severity:             vulnerability.SeverityCritical,
		CVSSv3:               ptr(9.8),
		PublishedAt:          now(),
		ExploitAvailable:     true,
		ExploitationObserved: true,
	}
}

func noExploitVulnerabilityParams() vulnerability.Params {
	return vulnerability.Params{
		CVEID:       "CVE-2026-00002",
		Title:       "Low-impact information disclosure",
		Severity:    vulnerability.SeverityLow,
		CVSSv3:      ptr(3.1),
		PublishedAt: now(),
	}
}

func ptr(f float64) *float64 { return &f }

// TestFixtures reproduces the AGENTS.md §36 fixtures: a critical,
// internet-exposed asset with a known exploited vulnerability must score
// higher than a low-criticality, internal-only asset with no exploit —
// and, per §44 Invariant 5, the resulting score must not simply equal the
// vulnerability's CVSS value.
func TestFixtures(t *testing.T) {
	e := newTestEngine(t, BusinessImpact{BusinessCriticality: "critical"})

	high := buildInput(t, criticalExposedAssetParams(), kevVulnerabilityParams())
	highAssessment, err := e.Assess(high)
	if err != nil {
		t.Fatalf("Assess(high) unexpected error: %v", err)
	}

	e2 := newTestEngine(t, BusinessImpact{})
	low := buildInput(t, lowInternalAssetParams(), noExploitVulnerabilityParams())
	lowAssessment, err := e2.Assess(low)
	if err != nil {
		t.Fatalf("Assess(low) unexpected error: %v", err)
	}

	if highAssessment.Score <= lowAssessment.Score {
		t.Errorf("high-risk score %.1f is not greater than low-risk score %.1f", highAssessment.Score, lowAssessment.Score)
	}
	if highAssessment.Level != LevelCritical {
		t.Errorf("high-risk level = %s, want %s", highAssessment.Level, LevelCritical)
	}
	if lowAssessment.Level == LevelCritical {
		t.Errorf("low-risk level = %s, want something less than %s", lowAssessment.Level, LevelCritical)
	}
	if highAssessment.Score == *high.Vulnerability.CVSSv3 {
		t.Error("risk score must not equal raw CVSS (AGENTS.md §44 Invariant 5)")
	}
	if len(highAssessment.Factors) == 0 {
		t.Error("assessment has no explaining factors (AGENTS.md §40)")
	}
}
