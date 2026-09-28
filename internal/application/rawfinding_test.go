package application

import (
	"context"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

func mustRawFinding(t *testing.T, mutate func(*rawfinding.Params)) rawfinding.RawFinding {
	t.Helper()
	p := rawfinding.Params{
		Source:      "pownforge:nuclei",
		SourceRef:   "run-1:finding-1",
		AssetID:     asset.NewID(),
		Title:       "unset in test",
		Confidence:  finding.ConfidenceHigh,
		CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if mutate != nil {
		mutate(&p)
	}
	rf, err := rawfinding.New(p)
	if err != nil {
		t.Fatalf("rawfinding.New() unexpected error: %v", err)
	}
	return *rf
}

// TestMatchRawFindingCorrelatesKnownCVE is the happy path: a RawFinding
// naming a CVE that already has a Vulnerability record produces a Finding
// via the existing CorrelateFindings Named API (AGENTS.md §26).
func TestMatchRawFindingCorrelatesKnownCVE(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()

	a, err := svc.DiscoverAssets(ctx, testAssetParams(), testAssetParams().FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}
	v, err := vulnerability.New(vulnerability.Params{
		CVEID:       "CVE-2021-44228",
		Title:       "Log4Shell",
		Severity:    vulnerability.SeverityCritical,
		PublishedAt: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("vulnerability.New() unexpected error: %v", err)
	}
	if err := repos.vulnerabilities.Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}

	rf := mustRawFinding(t, func(p *rawfinding.Params) {
		p.AssetID = a.ID
		p.Title = "[CVE-2021-44228] Log4Shell RCE"
	})

	f, outcome, err := svc.MatchRawFinding(ctx, rf)
	if err != nil {
		t.Fatalf("MatchRawFinding() unexpected error: %v", err)
	}
	if outcome != MatchOutcomeCorrelated {
		t.Fatalf("outcome = %q, want %q", outcome, MatchOutcomeCorrelated)
	}
	if f == nil || f.VulnerabilityID != v.ID || f.AssetID != a.ID {
		t.Errorf("MatchRawFinding() finding = %+v, want asset %s / vulnerability %s", f, a.ID, v.ID)
	}
	if f.DetectionSource != rf.Source {
		t.Errorf("DetectionSource = %q, want %q", f.DetectionSource, rf.Source)
	}
}

// TestMatchRawFindingIsIdempotent confirms two RawFindings for the same
// (asset, CVE) confirm the same Finding rather than creating a duplicate
// (AGENTS.md §20A.7 / §37), by way of CorrelateFindings's own idempotency.
func TestMatchRawFindingIsIdempotent(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()

	a, err := svc.DiscoverAssets(ctx, testAssetParams(), testAssetParams().FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}
	v, err := vulnerability.New(vulnerability.Params{
		CVEID:       "CVE-2021-44228",
		Title:       "Log4Shell",
		Severity:    vulnerability.SeverityCritical,
		PublishedAt: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("vulnerability.New() unexpected error: %v", err)
	}
	if err := repos.vulnerabilities.Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}

	rf := mustRawFinding(t, func(p *rawfinding.Params) {
		p.AssetID = a.ID
		p.Title = "[CVE-2021-44228] Log4Shell RCE"
	})

	first, _, err := svc.MatchRawFinding(ctx, rf)
	if err != nil {
		t.Fatalf("MatchRawFinding() first call unexpected error: %v", err)
	}

	rf2 := mustRawFinding(t, func(p *rawfinding.Params) {
		p.AssetID = a.ID
		p.Title = "[CVE-2021-44228] Log4Shell RCE"
		p.CollectedAt = rf.CollectedAt.Add(48 * time.Hour)
	})
	second, outcome, err := svc.MatchRawFinding(ctx, rf2)
	if err != nil {
		t.Fatalf("MatchRawFinding() second call unexpected error: %v", err)
	}
	if outcome != MatchOutcomeCorrelated {
		t.Fatalf("outcome = %q, want %q", outcome, MatchOutcomeCorrelated)
	}
	if first.ID != second.ID {
		t.Errorf("second MatchRawFinding() created a new finding: %s != %s", first.ID, second.ID)
	}
	if len(repos.findings.byID) != 1 {
		t.Errorf("finding repository has %d records, want 1", len(repos.findings.byID))
	}
}

// TestMatchRawFindingUnmatchedWhenVulnerabilityNotRegistered covers a
// RawFinding naming a CVE RiskForge has no Vulnerability record for yet --
// out of scope to auto-create one here (ADR 0016).
func TestMatchRawFindingUnmatchedWhenVulnerabilityNotRegistered(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	rf := mustRawFinding(t, func(p *rawfinding.Params) {
		p.Title = "[CVE-2099-99999] not a real vulnerability record"
	})

	f, outcome, err := svc.MatchRawFinding(ctx, rf)
	if err != nil {
		t.Fatalf("MatchRawFinding() unexpected error: %v", err)
	}
	if outcome != MatchOutcomeUnmatched {
		t.Errorf("outcome = %q, want %q", outcome, MatchOutcomeUnmatched)
	}
	if f != nil {
		t.Errorf("MatchRawFinding() finding = %+v, want nil", f)
	}
}

// TestMatchRawFindingHeldWhenUnclassified covers AGENTS.md §20A.2 case 3:
// no CVE and low/unknown Confidence. This Matcher slice does not act on it
// yet (ADR 0016/0017 "対象外").
func TestMatchRawFindingHeldWhenUnclassified(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()

	rf := mustRawFinding(t, func(p *rawfinding.Params) {
		p.Title = "unusual response length"
		p.Confidence = finding.ConfidenceLow
	})

	f, outcome, err := svc.MatchRawFinding(ctx, rf)
	if err != nil {
		t.Fatalf("MatchRawFinding() unexpected error: %v", err)
	}
	if outcome != MatchOutcomeHeld {
		t.Errorf("outcome = %q, want %q", outcome, MatchOutcomeHeld)
	}
	if f != nil {
		t.Errorf("MatchRawFinding() finding = %+v, want nil", f)
	}

	// AGENTS.md §20A.2 case 3 says "保留する" (hold), not discard --
	// confirm it's actually retrievable, not just silently dropped.
	saved, err := repos.rawFindings.FindByID(ctx, rf.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if saved == nil || saved.Title != rf.Title {
		t.Errorf("held rawfinding = %+v, want it persisted as %+v", saved, rf)
	}
}

// TestMatchRawFindingRegistersUnknownVulnerability covers AGENTS.md
// §20A.2 case 2: no CVE, but decent Confidence -- registered as a new,
// CVE-less Vulnerability (ADR 0017).
func TestMatchRawFindingRegistersUnknownVulnerability(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()

	a, err := svc.DiscoverAssets(ctx, testAssetParams(), testAssetParams().FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}

	rf := mustRawFinding(t, func(p *rawfinding.Params) {
		p.AssetID = a.ID
		p.Source = "pownforge:iac"
		p.Title = "CKV_DOCKER_8: Ensure the last USER is not root"
		p.Confidence = finding.ConfidenceHigh
	})

	f, outcome, err := svc.MatchRawFinding(ctx, rf)
	if err != nil {
		t.Fatalf("MatchRawFinding() unexpected error: %v", err)
	}
	if outcome != MatchOutcomeRegistered {
		t.Fatalf("outcome = %q, want %q", outcome, MatchOutcomeRegistered)
	}
	if f == nil || f.AssetID != a.ID {
		t.Fatalf("MatchRawFinding() finding = %+v, want one for asset %s", f, a.ID)
	}

	v, err := repos.vulnerabilities.FindByID(ctx, f.VulnerabilityID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("registered vulnerability not found")
	}
	if v.CVEID != "" {
		t.Errorf("CVEID = %q, want empty", v.CVEID)
	}
	if v.Title != rf.Title {
		t.Errorf("Title = %q, want %q", v.Title, rf.Title)
	}
	if v.Severity != vulnerability.SeverityUnknown {
		t.Errorf("Severity = %q, want %q (iac plugin reports no native_severity)", v.Severity, vulnerability.SeverityUnknown)
	}
	if v.Provenance.Source != rf.Source || v.Provenance.SourceID != rf.Title {
		t.Errorf("Provenance = %+v, want Source=%q SourceID=%q", v.Provenance, rf.Source, rf.Title)
	}
}

// TestMatchRawFindingUnknownVulnerabilityIsIdempotent confirms two
// RawFindings for the same (Source, Title) reuse the same Vulnerability
// and confirm the same Finding, rather than registering a duplicate
// (AGENTS.md §20A.7 / §37), mirroring TestMatchRawFindingIsIdempotent's
// known-CVE case.
func TestMatchRawFindingUnknownVulnerabilityIsIdempotent(t *testing.T) {
	svc, repos := newTestService(t)
	ctx := context.Background()

	a, err := svc.DiscoverAssets(ctx, testAssetParams(), testAssetParams().FirstSeen)
	if err != nil {
		t.Fatalf("DiscoverAssets() unexpected error: %v", err)
	}

	rf := mustRawFinding(t, func(p *rawfinding.Params) {
		p.AssetID = a.ID
		p.Source = "pownforge:iac"
		p.Title = "CKV_DOCKER_8: Ensure the last USER is not root"
		p.Confidence = finding.ConfidenceHigh
	})
	first, _, err := svc.MatchRawFinding(ctx, rf)
	if err != nil {
		t.Fatalf("MatchRawFinding() first call unexpected error: %v", err)
	}

	rf2 := mustRawFinding(t, func(p *rawfinding.Params) {
		p.AssetID = a.ID
		p.Source = "pownforge:iac"
		p.Title = "CKV_DOCKER_8: Ensure the last USER is not root"
		p.Confidence = finding.ConfidenceHigh
		p.CollectedAt = rf.CollectedAt.Add(48 * time.Hour)
	})
	second, outcome, err := svc.MatchRawFinding(ctx, rf2)
	if err != nil {
		t.Fatalf("MatchRawFinding() second call unexpected error: %v", err)
	}
	if outcome != MatchOutcomeRegistered {
		t.Fatalf("outcome = %q, want %q", outcome, MatchOutcomeRegistered)
	}
	if first.VulnerabilityID != second.VulnerabilityID {
		t.Errorf("second MatchRawFinding() registered a new vulnerability: %s != %s", first.VulnerabilityID, second.VulnerabilityID)
	}
	if first.ID != second.ID {
		t.Errorf("second MatchRawFinding() created a new finding: %s != %s", first.ID, second.ID)
	}
	if len(repos.vulnerabilities.byID) != 1 {
		t.Errorf("vulnerability repository has %d records, want 1", len(repos.vulnerabilities.byID))
	}
}

// TestSeverityFromRawFinding covers the NativeSeverity -> Severity mapping
// (ADR 0017), including the two cases that are not a direct 1:1 string
// match.
func TestSeverityFromRawFinding(t *testing.T) {
	tests := []struct {
		name           string
		nativeSeverity string
		want           vulnerability.Severity
	}{
		{name: "critical", nativeSeverity: "critical", want: vulnerability.SeverityCritical},
		{name: "case insensitive", nativeSeverity: "HIGH", want: vulnerability.SeverityHigh},
		{name: "medium", nativeSeverity: "medium", want: vulnerability.SeverityMedium},
		{name: "low", nativeSeverity: "low", want: vulnerability.SeverityLow},
		{name: "nuclei info has no RiskForge equivalent, maps to none", nativeSeverity: "info", want: vulnerability.SeverityNone},
		{name: "empty (e.g. checkov, which reports no native_severity) maps to unknown", nativeSeverity: "", want: vulnerability.SeverityUnknown},
		{name: "unrecognized value maps to unknown rather than guessing", nativeSeverity: "weird", want: vulnerability.SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := rawfinding.RawFinding{NativeSeverity: tt.nativeSeverity}
			if got := severityFromRawFinding(rf); got != tt.want {
				t.Errorf("severityFromRawFinding(NativeSeverity=%q) = %q, want %q", tt.nativeSeverity, got, tt.want)
			}
		})
	}
}
