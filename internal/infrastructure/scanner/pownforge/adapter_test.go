package pownforge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
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
	"evidence": {
		"command": ["nuclei", "-u", "http://127.0.0.1:8918", "-jsonl"],
		"started_at": "2026-09-28T12:00:08Z",
		"finished_at": "2026-09-28T12:00:09Z",
		"returncode": 0,
		"stdout_sha256": "5f36307a583913b27cf17090793c0b9dd97aaa86958d06811773daee03c719f2",
		"stderr_sha256": "9362b032bcb7342f2ad38091d3fd48f63a03c5da6d72dbcd9ac3d86e0a5ec53c",
		"tool_version": "Nuclei Engine Version: v3.11.1"
	},
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
	rawFindings, err := Normalize([]byte(sampleRunRecordJSON), assetID, "")
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
	if _, err := Normalize([]byte("not json"), asset.NewID(), ""); err == nil {
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
	rawFindings, err := Normalize([]byte(payload), asset.NewID(), "")
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
	rawFindings, err := Normalize([]byte(payload), asset.NewID(), "")
	if err != nil {
		t.Fatalf("Normalize() unexpected error: %v", err)
	}
	if len(rawFindings) != 1 || rawFindings[0].Source != "pownforge" {
		t.Errorf("Normalize() Source = %q, want %q", rawFindings[0].Source, "pownforge")
	}
}

// TestFetch runs against a real httptest.Server (not a mock of net/http),
// serving the exact path shape PownForge's `GET /api/runs/{run_id}`
// returns (src/pownforge/web/routers/runs.py), to confirm Fetch builds the
// right URL and returns the body Normalize can then parse.
func TestFetch(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(sampleRunRecordJSON))
	}))
	defer server.Close()

	body, err := Fetch(context.Background(), server.URL, "run-abc123")
	if err != nil {
		t.Fatalf("Fetch() unexpected error: %v", err)
	}
	if gotPath != "/api/runs/run-abc123" {
		t.Errorf("requested path = %q, want %q", gotPath, "/api/runs/run-abc123")
	}

	rawFindings, err := Normalize(body, asset.NewID(), "")
	if err != nil {
		t.Fatalf("Normalize(Fetch() result) unexpected error: %v", err)
	}
	if len(rawFindings) != 3 {
		t.Errorf("Normalize(Fetch() result) returned %d RawFindings, want 3", len(rawFindings))
	}
}

// TestFetchTrimsTrailingSlashFromBaseURL confirms
// "http://host:port/" and "http://host:port" produce the same request path.
func TestFetchTrimsTrailingSlashFromBaseURL(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"run_id":"r","target":"t","plugin":"p","created_at":"2026-01-01T00:00:00Z","findings":[]}`))
	}))
	defer server.Close()

	if _, err := Fetch(context.Background(), server.URL+"/", "run-1"); err != nil {
		t.Fatalf("Fetch() unexpected error: %v", err)
	}
	if gotPath != "/api/runs/run-1" {
		t.Errorf("requested path = %q, want %q", gotPath, "/api/runs/run-1")
	}
}

// TestFetchReturnsErrorOnNon200 confirms a non-200 response (e.g. the
// run-id doesn't exist, PownForge returns 404) becomes a Go error rather
// than being silently treated as a body to parse.
func TestFetchReturnsErrorOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"run not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	if _, err := Fetch(context.Background(), server.URL, "does-not-exist"); err == nil {
		t.Error("Fetch() with a 404 response: want error, got nil")
	}
}

func TestExtractEvidence(t *testing.T) {
	assetID := asset.NewID()
	params, err := ExtractEvidence([]byte(sampleRunRecordJSON), assetID)
	if err != nil {
		t.Fatalf("ExtractEvidence() unexpected error: %v", err)
	}

	if params.Type != evidence.TypeDetectionResult {
		t.Errorf("Type = %q, want %q", params.Type, evidence.TypeDetectionResult)
	}
	if params.Source != "pownforge:nuclei" {
		t.Errorf("Source = %q, want %q", params.Source, "pownforge:nuclei")
	}
	if params.SourceRef != "run-abc123" {
		t.Errorf("SourceRef = %q, want %q", params.SourceRef, "run-abc123")
	}
	if params.AssetID != assetID {
		t.Errorf("AssetID = %q, want %q", params.AssetID, assetID)
	}
	if params.ContentHash != "5f36307a583913b27cf17090793c0b9dd97aaa86958d06811773daee03c719f2" {
		t.Errorf("ContentHash = %q, want the run's stdout_sha256", params.ContentHash)
	}
	if params.CollectedAt.IsZero() {
		t.Error("CollectedAt is zero, want evidence.finished_at")
	}
	if params.Location != "" {
		t.Errorf("Location = %q, want empty (the caller fills it in)", params.Location)
	}
}

func TestExtractEvidencePrefersResultSHA256OverStdoutSHA256(t *testing.T) {
	// The motivating case (ADR 0023): a plugin like `container` (trivy)
	// writes its findings to a file, leaving stdout empty -- stdout_sha256
	// here is deliberately the hash of "" to mirror that, and must NOT be
	// what ContentHash ends up as.
	payload := `{
		"run_id": "run-container-1", "target": "nginx-image-scan", "plugin": "container",
		"created_at": "2026-09-30T00:00:00Z",
		"evidence": {
			"command": ["trivy", "image", "nginx:1.27"],
			"started_at": "2026-09-30T00:00:00Z",
			"finished_at": "2026-09-30T00:00:05Z",
			"returncode": 0,
			"stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"result_sha256": "73cab4f6632e126c8429236586712f5253c4bd3a8121aa312fbd1b1ea93bffea",
			"tool_version": "Version: 0.74.0"
		},
		"findings": []
	}`
	params, err := ExtractEvidence([]byte(payload), asset.NewID())
	if err != nil {
		t.Fatalf("ExtractEvidence() unexpected error: %v", err)
	}
	if params.ContentHash != "73cab4f6632e126c8429236586712f5253c4bd3a8121aa312fbd1b1ea93bffea" {
		t.Errorf("ContentHash = %q, want the run's result_sha256 (not stdout_sha256)", params.ContentHash)
	}
}

func TestExtractEvidenceFallsBackToStdoutSHA256WhenResultSHA256Absent(t *testing.T) {
	// A PownForge run saved before result_sha256 existed (or a PownForge
	// version predating it): result_sha256 is absent from the JSON
	// entirely, not just empty -- ContentHash must fall back to
	// stdout_sha256 rather than ending up empty.
	payload := `{
		"run_id": "run-old-1", "target": "lab-web", "plugin": "nuclei",
		"created_at": "2026-09-28T12:00:00Z",
		"evidence": {
			"command": ["nuclei", "-u", "http://127.0.0.1:8918"],
			"started_at": "2026-09-28T12:00:08Z",
			"finished_at": "2026-09-28T12:00:09Z",
			"returncode": 0,
			"stdout_sha256": "5f36307a583913b27cf17090793c0b9dd97aaa86958d06811773daee03c719f2",
			"stderr_sha256": "9362b032bcb7342f2ad38091d3fd48f63a03c5da6d72dbcd9ac3d86e0a5ec53c",
			"tool_version": "Nuclei Engine Version: v3.11.1"
		},
		"findings": []
	}`
	params, err := ExtractEvidence([]byte(payload), asset.NewID())
	if err != nil {
		t.Fatalf("ExtractEvidence() unexpected error: %v", err)
	}
	if params.ContentHash != "5f36307a583913b27cf17090793c0b9dd97aaa86958d06811773daee03c719f2" {
		t.Errorf("ContentHash = %q, want the run's stdout_sha256 as fallback", params.ContentHash)
	}
}

func TestExtractEvidenceFallsBackToCreatedAtWhenFinishedAtIsMissing(t *testing.T) {
	payload := `{
		"run_id": "run-1", "target": "lab", "plugin": "checkov",
		"created_at": "2026-01-01T00:00:00Z",
		"findings": []
	}`
	params, err := ExtractEvidence([]byte(payload), asset.NewID())
	if err != nil {
		t.Fatalf("ExtractEvidence() unexpected error: %v", err)
	}
	if !params.CollectedAt.Equal(mustParseTime(t, "2026-01-01T00:00:00Z")) {
		t.Errorf("CollectedAt = %v, want run.created_at as fallback", params.CollectedAt)
	}
	if params.ContentHash != "" {
		t.Errorf("ContentHash = %q, want empty (no evidence sub-object in payload)", params.ContentHash)
	}
}

func TestExtractEvidenceRejectsMalformedPayload(t *testing.T) {
	if _, err := ExtractEvidence([]byte("not json"), asset.NewID()); err == nil {
		t.Error("ExtractEvidence() with malformed JSON: want error, got nil")
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("time.Parse(%q): %v", s, err)
	}
	return parsed
}
