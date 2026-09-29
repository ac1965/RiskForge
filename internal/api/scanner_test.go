package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// statefulAssetsRepo mirrors exceptions_test.go's statefulFindingsRepo/
// statefulExceptionsRepo pattern: api_test.go's assetsFake is stateless
// (Save/FindByHostname are no-ops that never actually find anything),
// which is fine for the read-only list tests but not for these tests --
// MatchRawFinding's success path genuinely requires FindByID to find the
// Asset that was just Saved (by AssetID, or by DiscoverAssets when
// resolving --target).
type statefulAssetsRepo struct {
	byID       map[asset.ID]*asset.Asset
	byHostname map[string]*asset.Asset
}

func newStatefulAssetsRepo() *statefulAssetsRepo {
	return &statefulAssetsRepo{byID: map[asset.ID]*asset.Asset{}, byHostname: map[string]*asset.Asset{}}
}

func (r *statefulAssetsRepo) Save(_ context.Context, a *asset.Asset) error {
	r.byID[a.ID] = a
	r.byHostname[a.Hostname] = a
	return nil
}
func (r *statefulAssetsRepo) FindByID(_ context.Context, id asset.ID) (*asset.Asset, error) {
	return r.byID[id], nil
}
func (r *statefulAssetsRepo) FindByHostname(_ context.Context, hostname string) (*asset.Asset, error) {
	return r.byHostname[hostname], nil
}
func (r *statefulAssetsRepo) List(context.Context) ([]*asset.Asset, error) {
	out := make([]*asset.Asset, 0, len(r.byID))
	for _, a := range r.byID {
		out = append(out, a)
	}
	return out, nil
}

// statefulVulnerabilitiesRepo is the same pattern as statefulAssetsRepo:
// matchUnknownVulnerability (ADR 0017) registers a new Vulnerability and
// immediately relies on CorrelateFindings finding it again by ID, which
// api_test.go's stateless vulnerabilitiesFake can't do.
type statefulVulnerabilitiesRepo struct {
	byID map[vulnerability.ID]*vulnerability.Vulnerability
}

func newStatefulVulnerabilitiesRepo() *statefulVulnerabilitiesRepo {
	return &statefulVulnerabilitiesRepo{byID: map[vulnerability.ID]*vulnerability.Vulnerability{}}
}

func (r *statefulVulnerabilitiesRepo) Save(_ context.Context, v *vulnerability.Vulnerability) error {
	r.byID[v.ID] = v
	return nil
}
func (r *statefulVulnerabilitiesRepo) FindByID(_ context.Context, id vulnerability.ID) (*vulnerability.Vulnerability, error) {
	return r.byID[id], nil
}
func (r *statefulVulnerabilitiesRepo) FindByCVE(_ context.Context, cveID string) (*vulnerability.Vulnerability, error) {
	for _, v := range r.byID {
		if v.CVEID == cveID {
			return v, nil
		}
	}
	return nil, nil
}
func (r *statefulVulnerabilitiesRepo) FindByProvenanceSourceID(_ context.Context, source, sourceID string) (*vulnerability.Vulnerability, error) {
	for _, v := range r.byID {
		if v.Provenance.Source == source && v.Provenance.SourceID == sourceID {
			return v, nil
		}
	}
	return nil, nil
}
func (r *statefulVulnerabilitiesRepo) List(context.Context) ([]*vulnerability.Vulnerability, error) {
	out := make([]*vulnerability.Vulnerability, 0, len(r.byID))
	for _, v := range r.byID {
		out = append(out, v)
	}
	return out, nil
}

// fakeNormalizePownForge/fakeFetchPownForge let each test control exactly
// what POST /api/v1/scanner/pownforge-import's normalize/fetch steps
// return, without depending on internal/infrastructure/scanner/pownforge
// (this package must not import it -- see api.go's NewMux doc comment).

func fakeNormalizePownForge(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error) {
	var body struct {
		Findings []struct {
			Title string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, err
	}
	out := make([]rawfinding.RawFinding, 0, len(body.Findings))
	for _, f := range body.Findings {
		rf, err := rawfinding.New(rawfinding.Params{
			Source: "fake", AssetID: assetID, Title: f.Title,
			Confidence: finding.ConfidenceMedium, CollectedAt: time.Now(),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, *rf)
	}
	return out, nil
}

func fakeFetchPownForge(_ context.Context, baseURL, runID string) ([]byte, error) {
	if baseURL == "" || runID == "" {
		return nil, errors.New("fakeFetchPownForge: empty baseURL/runID")
	}
	return []byte(`{"findings":[{"title":"fetched finding"}]}`), nil
}

func newTestMuxWithPownForge(t *testing.T, f testServiceFakes) http.Handler {
	t.Helper()
	return NewMux(newTestService(t, f), fakeNormalizePownForge, fakeFetchPownForge)
}

// seededAssetsRepo returns a statefulAssetsRepo with one Asset already
// saved under id, for tests that pass AssetID directly (MatchRawFinding's
// success path requires the Asset to already exist).
func seededAssetsRepo(id asset.ID) *statefulAssetsRepo {
	r := newStatefulAssetsRepo()
	r.byID[id] = &asset.Asset{ID: id, Hostname: "seeded"}
	return r
}

func TestImportPownForge_EmbeddedRunRecordWithAssetID(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{assetsRepo: seededAssetsRepo("asset-1"), vulnerabilitiesRepo: newStatefulVulnerabilitiesRepo()})

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"RunRecord": json.RawMessage(`{"findings":[{"title":"finding A"},{"title":"finding B"}]}`),
		"AssetID":   "asset-1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var results []pownforgeImportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 2 || results[0].Title != "finding A" || results[1].Title != "finding B" {
		t.Errorf("results = %+v, want 2 findings titled A and B", results)
	}
}

func TestImportPownForge_FetchWithRunID(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{assetsRepo: seededAssetsRepo("asset-1"), vulnerabilitiesRepo: newStatefulVulnerabilitiesRepo()})

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"PownForgeURL": "http://127.0.0.1:8000",
		"RunID":        "run-1",
		"AssetID":      "asset-1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var results []pownforgeImportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 1 || results[0].Title != "fetched finding" {
		t.Errorf("results = %+v, want 1 finding titled %q", results, "fetched finding")
	}
}

// TestImportPownForge_TargetResolvesAsset is a regression test for the
// exact bug ADR 0020 found on the CLI side by hand: passing only Hostname
// to asset.Params (nothing else) makes asset.New reject it (Type is
// required). If resolveTargetAsset's defaults regress, DiscoverAssets
// fails and this returns 400, not 200.
func TestImportPownForge_TargetResolvesAsset(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{assetsRepo: newStatefulAssetsRepo(), vulnerabilitiesRepo: newStatefulVulnerabilitiesRepo()})

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"RunRecord": json.RawMessage(`{"findings":[{"title":"x"}]}`),
		"Target":    "lab-web",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestImportPownForge_RejectsBothRunRecordAndFetchParams(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{})

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"RunRecord":    json.RawMessage(`{"findings":[]}`),
		"PownForgeURL": "http://127.0.0.1:8000",
		"RunID":        "run-1",
		"AssetID":      "asset-1",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestImportPownForge_RejectsNeitherRunRecordNorFetchParams(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{})

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"AssetID": "asset-1",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestImportPownForge_RejectsBothAssetIDAndTarget(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{})

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"RunRecord": json.RawMessage(`{"findings":[]}`),
		"AssetID":   "asset-1",
		"Target":    "lab-web",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestImportPownForge_RejectsNeitherAssetIDNorTarget(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{})

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"RunRecord": json.RawMessage(`{"findings":[]}`),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestImportPownForge_RequiresScannerImportScope(t *testing.T) {
	mux := newTestMuxWithPownForge(t, testServiceFakes{})

	// testRawToken only carries ScopeRead, not ScopeScannerImport.
	rec := postJSON(t, mux, testRawToken, "/api/v1/scanner/pownforge-import", map[string]any{
		"RunRecord": json.RawMessage(`{"findings":[]}`),
		"AssetID":   "asset-1",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestImportPownForge_FetchFailureBecomes502(t *testing.T) {
	mux := NewMux(newTestService(t, testServiceFakes{}), fakeNormalizePownForge,
		func(context.Context, string, string) ([]byte, error) { return nil, errors.New("connection refused") })

	rec := postJSON(t, mux, testRawTokenScannerImport, "/api/v1/scanner/pownforge-import", map[string]any{
		"PownForgeURL": "http://127.0.0.1:8000",
		"RunID":        "run-1",
		"AssetID":      "asset-1",
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}
