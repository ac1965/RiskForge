package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// sampleFoundResponse is a trimmed-down real NVD CVE API 2.0 response for
// CVE-2022-1664 (confirmed against the live API, 2026-09-30) -- only the
// fields this package reads.
const sampleFoundResponse = `{
	"resultsPerPage": 1,
	"totalResults": 1,
	"vulnerabilities": [
		{
			"cve": {
				"id": "CVE-2022-1664",
				"published": "2022-05-26T14:15:08.010",
				"descriptions": [
					{"lang": "es", "value": "no en ingles"},
					{"lang": "en", "value": "Dpkg::Source::Archive in dpkg is prone to a directory traversal vulnerability."}
				],
				"metrics": {
					"cvssMetricV31": [
						{
							"source": "nvd@nist.gov",
							"type": "Primary",
							"cvssData": {
								"version": "3.1",
								"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								"baseScore": 9.8,
								"baseSeverity": "CRITICAL"
							}
						}
					]
				}
			}
		}
	]
}`

const sampleNotFoundResponse = `{"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}`

func newTestServer(t *testing.T, status int, body string) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cveId"); got == "" {
			t.Errorf("request missing cveId query param")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &Client{baseURL: server.URL, apiKey: ""}
}

func TestLookupCVEParsesRealResponseShape(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, sampleFoundResponse)

	params, err := client.LookupCVE(context.Background(), "CVE-2022-1664")
	if err != nil {
		t.Fatalf("LookupCVE() unexpected error: %v", err)
	}
	if params == nil {
		t.Fatal("LookupCVE() = nil, want a result")
	}
	if params.CVEID != "CVE-2022-1664" {
		t.Errorf("CVEID = %q, want CVE-2022-1664", params.CVEID)
	}
	if params.Description != "Dpkg::Source::Archive in dpkg is prone to a directory traversal vulnerability." {
		t.Errorf("Description = %q, want the English description (not Spanish)", params.Description)
	}
	if params.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", params.Severity)
	}
	if params.CVSSv3 == nil || *params.CVSSv3 != 9.8 {
		t.Errorf("CVSSv3 = %v, want 9.8", params.CVSSv3)
	}
	if params.PublishedAt.IsZero() {
		t.Error("PublishedAt is zero, want NVD's published timestamp")
	}
	if params.Provenance.Source != "nvd" {
		t.Errorf("Provenance.Source = %q, want nvd", params.Provenance.Source)
	}
	if params.Provenance.SourceID != "CVE-2022-1664" {
		t.Errorf("Provenance.SourceID = %q, want CVE-2022-1664", params.Provenance.SourceID)
	}
}

func TestLookupCVEReturnsNilNilWhenNotFound(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, sampleNotFoundResponse)

	params, err := client.LookupCVE(context.Background(), "CVE-2099-99999")
	if err != nil {
		t.Fatalf("LookupCVE() unexpected error: %v", err)
	}
	if params != nil {
		t.Errorf("LookupCVE() = %+v, want nil (not found is not an error)", params)
	}
}

func TestLookupCVEReturnsErrorOnNon200(t *testing.T) {
	_, client := newTestServer(t, http.StatusTooManyRequests, "rate limited")

	if _, err := client.LookupCVE(context.Background(), "CVE-2022-1664"); err == nil {
		t.Error("LookupCVE() with 429 response: want error, got nil")
	}
}

func TestLookupCVEReturnsErrorOnMalformedJSON(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, "not json")

	if _, err := client.LookupCVE(context.Background(), "CVE-2022-1664"); err == nil {
		t.Error("LookupCVE() with malformed JSON: want error, got nil")
	}
}

func TestLookupCVELeavesCVSSNilWhenOnlyV2Available(t *testing.T) {
	// Deliberate scope limitation (ADR 0024): v2-only CVEs get no
	// CVSSv3/Severity rather than guessing from v2 data.
	body := `{
		"totalResults": 1,
		"vulnerabilities": [
			{"cve": {"id": "CVE-2005-1234", "published": "2005-01-01T00:00:00.000",
				"descriptions": [{"lang": "en", "value": "an old CVE"}],
				"metrics": {}
			}}
		]
	}`
	_, client := newTestServer(t, http.StatusOK, body)

	params, err := client.LookupCVE(context.Background(), "CVE-2005-1234")
	if err != nil {
		t.Fatalf("LookupCVE() unexpected error: %v", err)
	}
	if params.CVSSv3 != nil {
		t.Errorf("CVSSv3 = %v, want nil for a v2-only CVE", params.CVSSv3)
	}
	if params.Severity != "unknown" {
		t.Errorf("Severity = %q, want unknown for a v2-only CVE", params.Severity)
	}
}

func TestNewClientSetsAPIKeyHeader(t *testing.T) {
	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("apiKey")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleNotFoundResponse))
	}))
	defer server.Close()

	client := &Client{baseURL: server.URL, apiKey: "test-key-123"}
	if _, err := client.LookupCVE(context.Background(), "CVE-2022-1664"); err != nil {
		t.Fatalf("LookupCVE() unexpected error: %v", err)
	}
	if gotHeader != "test-key-123" {
		t.Errorf("apiKey header = %q, want test-key-123", gotHeader)
	}
}
