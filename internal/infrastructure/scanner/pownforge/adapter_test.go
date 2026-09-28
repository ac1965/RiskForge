package pownforge

import (
	"testing"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

// This RunRecord JSON shape mirrors what
// src/pownforge/core/models/evidence.py's RunRecord and
// src/pownforge/core/models/finding.py's Finding actually serialize to
// (field names confirmed against those files, not guessed). The nuclei
// finding is CVSS-less/info-severity like the golden fixture PownForge
// captured for robots-txt-endpoint (tests/golden/nuclei/); the vulncheck
// finding carries the NVD-sourced CVSS fields ADR 0017's severity mapping
// expects.
const sampleRunRecordJSON = `{
	"run_id": "run-abc123",
	"target": "lab-web",
	"plugin": "nuclei",
	"created_at": "2026-09-28T12:00:00Z",
	"findings": [
		{
			"finding_id": "f1",
			"title": "robots.txt endpoint prober",
			"detail": "",
			"severity": "info",
			"source": "tool",
			"status": "needs-review",
			"attack_technique_ids": [],
			"cvss_score": null,
			"cvss_vector": null,
			"native_severity": "info"
		},
		{
			"finding_id": "f2",
			"title": "OpenSSL Heartbleed (CVE-2014-0160)",
			"detail": "The Heartbleed Bug is a serious vulnerability.",
			"severity": "high",
			"source": "tool",
			"status": "confirmed",
			"attack_technique_ids": ["T1190"],
			"cvss_score": 7.5,
			"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"native_severity": "HIGH"
		},
		{
			"finding_id": "f3",
			"title": "AI-guessed possible misconfiguration",
			"detail": "unverified",
			"severity": "medium",
			"source": "ai",
			"status": "needs-review",
			"attack_technique_ids": [],
			"cvss_score": null,
			"cvss_vector": null,
			"native_severity": null
		},
		{
			"finding_id": "f4",
			"title": "reviewed and rejected",
			"detail": "turned out to be expected behavior",
			"severity": "low",
			"source": "manual",
			"status": "false-positive",
			"attack_technique_ids": [],
			"cvss_score": null,
			"cvss_vector": null,
			"native_severity": null
		}
	]
}`

func TestNormalize(t *testing.T) {
	assetID := asset.NewID()
	rawFindings, err := Normalize([]byte(sampleRunRecordJSON), assetID)
	if err != nil {
		t.Fatalf("Normalize() unexpected error: %v", err)
	}

	// f4 (false-positive) must be dropped entirely.
	if len(rawFindings) != 3 {
		t.Fatalf("Normalize() returned %d RawFindings, want 3 (false-positive excluded)", len(rawFindings))
	}

	byTitle := map[string]int{}
	for i, rf := range rawFindings {
		byTitle[rf.Title] = i
		if rf.AssetID != assetID {
			t.Errorf("RawFinding[%d].AssetID = %q, want %q", i, rf.AssetID, assetID)
		}
		if rf.Source != "pownforge:nuclei" {
			t.Errorf("RawFinding[%d].Source = %q, want %q", i, rf.Source, "pownforge:nuclei")
		}
		if rf.CollectedAt.IsZero() {
			t.Errorf("RawFinding[%d].CollectedAt is zero, want run.created_at", i)
		}
	}

	robots := rawFindings[byTitle["robots.txt endpoint prober"]]
	if robots.SourceRef != "run-abc123:f1" {
		t.Errorf("robots.SourceRef = %q, want %q", robots.SourceRef, "run-abc123:f1")
	}
	if robots.Confidence != finding.ConfidenceMedium {
		t.Errorf("robots.Confidence = %q, want %q (tool + needs-review)", robots.Confidence, finding.ConfidenceMedium)
	}
	if robots.CVSSScore != nil {
		t.Errorf("robots.CVSSScore = %v, want nil", robots.CVSSScore)
	}
	if robots.NativeSeverity != "info" {
		t.Errorf("robots.NativeSeverity = %q, want %q", robots.NativeSeverity, "info")
	}

	heartbleed := rawFindings[byTitle["OpenSSL Heartbleed (CVE-2014-0160)"]]
	if heartbleed.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("heartbleed.Confidence = %q, want %q (status=confirmed)", heartbleed.Confidence, finding.ConfidenceConfirmed)
	}
	if heartbleed.CVSSScore == nil || *heartbleed.CVSSScore != 7.5 {
		t.Errorf("heartbleed.CVSSScore = %v, want 7.5", heartbleed.CVSSScore)
	}
	if len(heartbleed.AttackTechniqueIDs) != 1 || heartbleed.AttackTechniqueIDs[0] != "T1190" {
		t.Errorf("heartbleed.AttackTechniqueIDs = %v, want [T1190]", heartbleed.AttackTechniqueIDs)
	}

	aiGuess := rawFindings[byTitle["AI-guessed possible misconfiguration"]]
	if aiGuess.Confidence != finding.ConfidenceLow {
		t.Errorf("aiGuess.Confidence = %q, want %q (source=ai + needs-review)", aiGuess.Confidence, finding.ConfidenceLow)
	}
}

func TestNormalizeRejectsMalformedPayload(t *testing.T) {
	if _, err := Normalize([]byte("not json"), asset.NewID()); err == nil {
		t.Error("Normalize() with malformed JSON: want error, got nil")
	}
}

func TestNormalizeSkipsFindingWithNoTitle(t *testing.T) {
	payload := `{
		"run_id": "run-1", "target": "lab", "plugin": "checkov",
		"created_at": "2026-01-01T00:00:00Z",
		"findings": [
			{"finding_id": "f1", "title": "", "status": "needs-review", "source": "tool"},
			{"finding_id": "f2", "title": "real finding", "status": "needs-review", "source": "tool"}
		]
	}`
	rawFindings, err := Normalize([]byte(payload), asset.NewID())
	if err != nil {
		t.Fatalf("Normalize() unexpected error: %v", err)
	}
	if len(rawFindings) != 1 || rawFindings[0].Title != "real finding" {
		t.Errorf("Normalize() = %+v, want only the finding with a non-empty title", rawFindings)
	}
}

func TestNormalizeDefaultsSourceWhenPluginIsEmpty(t *testing.T) {
	payload := `{
		"run_id": "run-1", "target": "lab", "plugin": "",
		"created_at": "2026-01-01T00:00:00Z",
		"findings": [{"finding_id": "f1", "title": "x", "status": "needs-review", "source": "manual"}]
	}`
	rawFindings, err := Normalize([]byte(payload), asset.NewID())
	if err != nil {
		t.Fatalf("Normalize() unexpected error: %v", err)
	}
	if len(rawFindings) != 1 || rawFindings[0].Source != "pownforge" {
		t.Errorf("Normalize() Source = %q, want %q", rawFindings[0].Source, "pownforge")
	}
}
