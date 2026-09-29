// Package nvd implements application.VulnerabilityLookup (ADR 0024)
// against the NVD CVE API 2.0 (https://nvd.nist.gov/developers/vulnerabilities),
// one of the AGENTS.md §19 Data Source Adapters. On-demand, single-CVE
// lookups only -- MatchRawFinding calls LookupCVE for one CVE at a time
// when its own Vulnerability catalog has no record for it yet. A bulk/
// periodic full-catalog sync is a different, larger feature and out of
// scope here.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// DefaultBaseURL is NVD's public CVE API 2.0 endpoint.
const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// httpClient is package-level so tests can point Client at an
// httptest.Server without a global timeout mismatch; production code
// never overrides it.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// maxResponseBytes caps how much of an NVD response Client will read --
// defensive, NVD itself has no documented cap for a single-CVE lookup.
const maxResponseBytes = 5 << 20 // 5MiB

// Client implements application.VulnerabilityLookup against the NVD CVE
// API 2.0. APIKey is optional: NVD allows unauthenticated access at a
// lower rate limit (5 requests / 30s as of this writing); passing a key
// (via the `apiKey` header) raises that limit. Client does not itself
// retry or rate-limit -- a caller issuing many lookups in a tight loop is
// expected to pace itself.
type Client struct {
	baseURL string
	apiKey  string
}

// NewClient returns a Client. apiKey may be "" for unauthenticated,
// rate-limited access.
func NewClient(apiKey string) *Client {
	return &Client{baseURL: DefaultBaseURL, apiKey: apiKey}
}

// cveAPIResponse mirrors the fields of NVD CVE API 2.0's response this
// package actually uses (confirmed against a real response for
// CVE-2022-1664, 2026-09-30) -- not the full schema.
type cveAPIResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []cvssMetric `json:"cvssMetricV31"`
				CvssMetricV30 []cvssMetric `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type cvssMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// nvdPublishedLayout is NVD's own timestamp format for `published`
// (no timezone, millisecond precision) -- confirmed against a real
// response, e.g. "2022-05-26T14:15:08.010".
const nvdPublishedLayout = "2006-01-02T15:04:05.000"

// LookupCVE implements application.VulnerabilityLookup. Only CVSS v3.1/
// v3.0 metrics are used (whichever NVD marks first, preferring v3.1) --
// a CVE with only a v2 score (rare; pre-dates CVSS v3 adoption) comes
// back with Severity/CVSSv3 left at their zero values rather than
// guessing from v2 data, a deliberate scope limitation (see ADR 0024
// "対象外").
func (c *Client) LookupCVE(ctx context.Context, cveID string) (*vulnerability.Params, error) {
	url := c.baseURL + "?cveId=" + cveID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("nvd: build request for %s: %w", url, err)
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("nvd: read response from %s: %w", url, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("nvd: response from %s exceeds %d bytes", url, maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd: %s returned %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed cveAPIResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("nvd: parse response from %s: %w", url, err)
	}
	if parsed.TotalResults == 0 || len(parsed.Vulnerabilities) == 0 {
		return nil, nil
	}
	cve := parsed.Vulnerabilities[0].CVE

	description := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			description = d.Value
			break
		}
	}

	severity := vulnerability.SeverityUnknown
	var cvssV3 *float64
	if metric, ok := firstCVSSv3(cve.Metrics.CvssMetricV31, cve.Metrics.CvssMetricV30); ok {
		score := metric.CVSSData.BaseScore
		cvssV3 = &score
		severity = mapSeverity(metric.CVSSData.BaseSeverity)
	}

	published, _ := time.Parse(nvdPublishedLayout, cve.Published)

	return &vulnerability.Params{
		CVEID:       cve.ID,
		Title:       cve.ID,
		Description: description,
		Severity:    severity,
		CVSSv3:      cvssV3,
		PublishedAt: published,
		Provenance: vulnerability.Provenance{
			Source:      "nvd",
			SourceID:    cve.ID,
			RetrievedAt: time.Now().UTC(),
		},
	}, nil
}

// firstCVSSv3 returns the first non-empty of v31, v30 (in that preference
// order, matching PownForge's own trivy/grype/nuclei/vulncheck CVSS
// preference -- see the PownForge sister repo's docs/handbook.md §3.5).
func firstCVSSv3(v31, v30 []cvssMetric) (cvssMetric, bool) {
	if len(v31) > 0 {
		return v31[0], true
	}
	if len(v30) > 0 {
		return v30[0], true
	}
	return cvssMetric{}, false
}

func mapSeverity(nvdBaseSeverity string) vulnerability.Severity {
	switch strings.ToUpper(nvdBaseSeverity) {
	case "CRITICAL":
		return vulnerability.SeverityCritical
	case "HIGH":
		return vulnerability.SeverityHigh
	case "MEDIUM":
		return vulnerability.SeverityMedium
	case "LOW":
		return vulnerability.SeverityLow
	default:
		return vulnerability.SeverityUnknown
	}
}
