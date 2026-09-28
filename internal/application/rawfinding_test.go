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

// TestMatchRawFindingHeldWhenNotAKnownVulnerability covers the other two
// Normalizer classifications (AGENTS.md §20A.2 cases 2 and 3), neither of
// which this Matcher slice acts on yet (ADR 0016 "対象外").
func TestMatchRawFindingHeldWhenNotAKnownVulnerability(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tests := []struct {
		name  string
		title string
		conf  finding.Confidence
	}{
		{name: "unknown vulnerability (no CVE, decent confidence)", title: "CKV_DOCKER_8: root user", conf: finding.ConfidenceHigh},
		{name: "unclassified (no CVE, low confidence)", title: "unusual response length", conf: finding.ConfidenceLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := mustRawFinding(t, func(p *rawfinding.Params) {
				p.Title = tt.title
				p.Confidence = tt.conf
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
		})
	}
}
