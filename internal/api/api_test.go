package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/authn"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
	"github.com/ac1965/riskforge/internal/domain/remediation"
	"github.com/ac1965/riskforge/internal/domain/risk"
	"github.com/ac1965/riskforge/internal/domain/software"
	"github.com/ac1965/riskforge/internal/domain/verification"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// The fakes below are minimal in-memory stand-ins for application's
// repository ports (mirroring internal/application/fakes_test.go), used
// only to build a *application.Service for this package's tests — not a
// real Infrastructure implementation.

type assetsFake struct {
	items []*asset.Asset
	err   error
}

func (f assetsFake) Save(context.Context, *asset.Asset) error                     { return nil }
func (f assetsFake) FindByID(context.Context, asset.ID) (*asset.Asset, error)     { return nil, nil }
func (f assetsFake) FindByHostname(context.Context, string) (*asset.Asset, error) { return nil, nil }
func (f assetsFake) List(context.Context) ([]*asset.Asset, error)                 { return f.items, f.err }

type findingsFake struct {
	items []*finding.Finding
	err   error
}

func (f findingsFake) Save(context.Context, *finding.Finding) error { return nil }
func (f findingsFake) FindByID(context.Context, finding.ID) (*finding.Finding, error) {
	return nil, nil
}
func (f findingsFake) FindByAssetAndVulnerability(context.Context, asset.ID, vulnerability.ID) (*finding.Finding, error) {
	return nil, nil
}
func (f findingsFake) List(context.Context) ([]*finding.Finding, error) { return f.items, f.err }

type priorityDecisionsFake struct {
	items []*priority.Decision
	err   error
}

func (f priorityDecisionsFake) Save(context.Context, *priority.Decision) error { return nil }
func (f priorityDecisionsFake) FindLatestByFinding(context.Context, finding.ID) (*priority.Decision, error) {
	return nil, nil
}
func (f priorityDecisionsFake) ListLatest(context.Context) ([]*priority.Decision, error) {
	return f.items, f.err
}

type remediationPlansFake struct {
	items []*remediation.Plan
	err   error
}

func (f remediationPlansFake) Save(context.Context, *remediation.Plan) error { return nil }
func (f remediationPlansFake) FindByID(context.Context, remediation.ID) (*remediation.Plan, error) {
	return nil, nil
}
func (f remediationPlansFake) List(context.Context) ([]*remediation.Plan, error) {
	return f.items, f.err
}

type exceptionsFake struct {
	items []*exception.Exception
	err   error
}

func (f exceptionsFake) Save(context.Context, *exception.Exception) error { return nil }
func (f exceptionsFake) FindByID(context.Context, exception.ID) (*exception.Exception, error) {
	return nil, nil
}
func (f exceptionsFake) List(context.Context) ([]*exception.Exception, error) {
	return f.items, f.err
}

// The remaining ports are never exercised by these tests (the five
// endpoints only read Assets/Findings/PriorityDecisions/
// RemediationPlans/Exceptions), so they get trivial no-op stand-ins that
// exist only to satisfy application.NewService's non-nil checks.

type softwareFake struct{}

func (softwareFake) Save(context.Context, *software.Installation) error { return nil }
func (softwareFake) FindByNaturalKey(context.Context, asset.ID, string, string, string) (*software.Installation, error) {
	return nil, nil
}

type vulnerabilitiesFake struct {
	items []*vulnerability.Vulnerability
	err   error
}

func (f vulnerabilitiesFake) Save(context.Context, *vulnerability.Vulnerability) error { return nil }
func (f vulnerabilitiesFake) FindByID(context.Context, vulnerability.ID) (*vulnerability.Vulnerability, error) {
	return nil, nil
}
func (f vulnerabilitiesFake) FindByCVE(context.Context, string) (*vulnerability.Vulnerability, error) {
	return nil, nil
}
func (f vulnerabilitiesFake) FindByProvenanceSourceID(context.Context, string, string) (*vulnerability.Vulnerability, error) {
	return nil, nil
}
func (f vulnerabilitiesFake) List(context.Context) ([]*vulnerability.Vulnerability, error) {
	return f.items, f.err
}

type riskAssessmentsFake struct{}

func (riskAssessmentsFake) Save(context.Context, *risk.Assessment) error { return nil }
func (riskAssessmentsFake) FindLatestByFinding(context.Context, finding.ID) (*risk.Assessment, error) {
	return nil, nil
}

type verificationsFake struct {
	items []*verification.Verification
	err   error
}

func (f verificationsFake) Save(context.Context, *verification.Verification) error { return nil }
func (f verificationsFake) List(context.Context) ([]*verification.Verification, error) {
	return f.items, f.err
}

type rawFindingsFake struct{}

func (rawFindingsFake) Save(context.Context, *rawfinding.RawFinding) error { return nil }
func (rawFindingsFake) FindByID(context.Context, rawfinding.ID) (*rawfinding.RawFinding, error) {
	return nil, nil
}
func (rawFindingsFake) List(context.Context) ([]*rawfinding.RawFinding, error) { return nil, nil }

type evidenceFake struct{}

func (evidenceFake) Save(context.Context, *evidence.Evidence) error { return nil }
func (evidenceFake) FindByID(context.Context, evidence.ID) (*evidence.Evidence, error) {
	return nil, nil
}

type auditFake struct{}

func (auditFake) Save(context.Context, *audit.Entry) error { return nil }

// testRawToken and testRawTokenWrongScope are fixed bearer tokens
// principalsFake/apiTokensFake recognize, standing in for tokens that
// would normally come from `riskforge token create`. Every test in this
// file that expects a successful call authenticates with testRawToken
// via the get() helper below; TestRequireScope_* exercises the rejection
// paths, including testRawTokenWrongScope's deliberately insufficient
// scope.
const (
	testRawToken                   = "rf_test-token-with-read-scope"
	testRawTokenWrongScope         = "rf_test-token-without-read-scope"
	testRawTokenExceptionRequester = "rf_test-token-exception-request-scope"
	testRawTokenExceptionApprover  = "rf_test-token-exception-approve-scope"
	testRawTokenScannerImport      = "rf_test-token-scanner-import-scope"
	testExceptionRequesterName     = "requester"
	testExceptionApproverName      = "approver"
)

var (
	testPrincipalID                 = authn.NewPrincipalID()
	testExceptionRequesterPrincipal = authn.NewPrincipalID()
	testExceptionApproverPrincipal  = authn.NewPrincipalID()
	testScannerImportPrincipal      = authn.NewPrincipalID()
)

type principalsFake struct{}

func (principalsFake) Save(context.Context, *authn.Principal) error { return nil }
func (principalsFake) FindByID(_ context.Context, id authn.PrincipalID) (*authn.Principal, error) {
	switch id {
	case testPrincipalID:
		return &authn.Principal{ID: testPrincipalID, Name: "test", Kind: authn.KindService, CreatedAt: time.Now()}, nil
	case testExceptionRequesterPrincipal:
		return &authn.Principal{ID: testExceptionRequesterPrincipal, Name: testExceptionRequesterName, Kind: authn.KindHuman, CreatedAt: time.Now()}, nil
	case testExceptionApproverPrincipal:
		return &authn.Principal{ID: testExceptionApproverPrincipal, Name: testExceptionApproverName, Kind: authn.KindHuman, CreatedAt: time.Now()}, nil
	case testScannerImportPrincipal:
		return &authn.Principal{ID: testScannerImportPrincipal, Name: "scanner-importer", Kind: authn.KindService, CreatedAt: time.Now()}, nil
	default:
		return nil, nil
	}
}
func (principalsFake) FindByName(context.Context, string) (*authn.Principal, error) {
	return nil, nil
}

type apiTokensFake struct{}

func (apiTokensFake) Save(context.Context, *authn.APIToken) error { return nil }
func (apiTokensFake) FindByID(context.Context, authn.TokenID) (*authn.APIToken, error) {
	return nil, nil
}
func (apiTokensFake) FindByTokenHash(_ context.Context, hash string) (*authn.APIToken, error) {
	switch hash {
	case authn.HashToken(testRawToken):
		return &authn.APIToken{
			ID: authn.NewTokenID(), PrincipalID: testPrincipalID,
			TokenHash: hash, Scopes: []string{authn.ScopeRead}, CreatedAt: time.Now(),
		}, nil
	case authn.HashToken(testRawTokenWrongScope):
		return &authn.APIToken{
			ID: authn.NewTokenID(), PrincipalID: testPrincipalID,
			TokenHash: hash, Scopes: []string{"other"}, CreatedAt: time.Now(),
		}, nil
	case authn.HashToken(testRawTokenExceptionRequester):
		return &authn.APIToken{
			ID: authn.NewTokenID(), PrincipalID: testExceptionRequesterPrincipal,
			TokenHash: hash, Scopes: []string{authn.ScopeExceptionRequest}, CreatedAt: time.Now(),
		}, nil
	case authn.HashToken(testRawTokenExceptionApprover):
		return &authn.APIToken{
			ID: authn.NewTokenID(), PrincipalID: testExceptionApproverPrincipal,
			TokenHash: hash, Scopes: []string{authn.ScopeExceptionApprove}, CreatedAt: time.Now(),
		}, nil
	case authn.HashToken(testRawTokenScannerImport):
		return &authn.APIToken{
			ID: authn.NewTokenID(), PrincipalID: testScannerImportPrincipal,
			TokenHash: hash, Scopes: []string{authn.ScopeScannerImport}, CreatedAt: time.Now(),
		}, nil
	default:
		return nil, nil
	}
}
func (apiTokensFake) List(context.Context) ([]*authn.APIToken, error) { return nil, nil }

// testServiceFakes bundles the fakes this package's tests configure per
// test case. findingsRepo/exceptionsRepo, when set, override
// findings/exceptions entirely — the write-endpoint tests
// (exceptions_test.go) need stateful repos (Save persists, FindByID
// finds it again), unlike the static items/err fakes the read-only list
// tests use.
type testServiceFakes struct {
	assets              assetsFake
	findings            findingsFake
	priorityDecisions   priorityDecisionsFake
	remediationPlans    remediationPlansFake
	exceptions          exceptionsFake
	vulnerabilities     vulnerabilitiesFake
	verifications       verificationsFake
	findingsRepo        application.FindingRepository
	exceptionsRepo      application.ExceptionRepository
	assetsRepo          application.AssetRepository
	vulnerabilitiesRepo application.VulnerabilityRepository
}

func newTestService(t *testing.T, f testServiceFakes) *application.Service {
	t.Helper()

	riskEngine, err := risk.NewEngine(
		risk.FromVulnerabilityProvider{},
		risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{},
		risk.FromAssetProvider{},
		risk.StaticBusinessImpactProvider{},
		risk.BaselinePolicy{},
	)
	if err != nil {
		t.Fatalf("build risk engine: %v", err)
	}

	priorityEngine, err := priority.NewEngine(
		risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{},
		risk.FromAssetProvider{},
		priority.FromVulnerabilityRemediationProvider{},
		priority.StaticBusinessConstraintsProvider{},
		priority.BaselinePolicy{},
		priority.NewDefaultSLAPolicy(),
	)
	if err != nil {
		t.Fatalf("build priority engine: %v", err)
	}

	var findings application.FindingRepository = f.findings
	if f.findingsRepo != nil {
		findings = f.findingsRepo
	}
	var exceptions application.ExceptionRepository = f.exceptions
	if f.exceptionsRepo != nil {
		exceptions = f.exceptionsRepo
	}
	var assets application.AssetRepository = f.assets
	if f.assetsRepo != nil {
		assets = f.assetsRepo
	}
	var vulnerabilities application.VulnerabilityRepository = f.vulnerabilities
	if f.vulnerabilitiesRepo != nil {
		vulnerabilities = f.vulnerabilitiesRepo
	}

	svc, err := application.NewService(application.Service{
		Assets:            assets,
		Software:          softwareFake{},
		Vulnerabilities:   vulnerabilities,
		RawFindings:       rawFindingsFake{},
		Findings:          findings,
		RiskAssessments:   riskAssessmentsFake{},
		PriorityDecisions: f.priorityDecisions,
		RemediationPlans:  f.remediationPlans,
		Verifications:     f.verifications,
		Evidence:          evidenceFake{},
		Exceptions:        exceptions,
		Audit:             auditFake{},
		Principals:        principalsFake{},
		APITokens:         apiTokensFake{},
		RiskEngine:        riskEngine,
		PriorityEngine:    priorityEngine,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	return svc
}

// stubNormalizePownForge/stubFetchPownForge satisfy NewMux's PownForge
// parameters (ADR 0021) for tests that don't exercise
// POST /api/v1/scanner/pownforge-import -- scanner_test.go supplies real
// fakes for the tests that do.
func stubNormalizePownForge([]byte, asset.ID) ([]rawfinding.RawFinding, error) {
	return nil, errors.New("stubNormalizePownForge: not exercised by this test")
}

func stubFetchPownForge(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("stubFetchPownForge: not exercised by this test")
}

// newTestMux is NewMux built from newTestService's fakes plus the stub
// PownForge functions, for the tests that never call the scanner
// endpoint.
func newTestMux(t *testing.T, f testServiceFakes) http.Handler {
	t.Helper()
	return NewMux(newTestService(t, f), stubNormalizePownForge, stubFetchPownForge)
}

// get issues an authenticated GET (RequireScope now gates every route
// this package serves). Tests of the middleware itself use getAs
// directly to control or omit the bearer token.
func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	return getAs(t, h, path, testRawToken)
}

// getAs issues a GET with rawToken as the bearer token, or with no
// Authorization header at all when rawToken is "".
func getAs(t *testing.T, h http.Handler, path, rawToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if rawToken != "" {
		req.Header.Set("Authorization", "Bearer "+rawToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestNewMux_EmptyListsAreJSONArrays verifies every endpoint returns `[]`
// (never `null`) when the underlying list is empty, matching ADR 0011's
// "the response is the resource array itself".
func TestNewMux_EmptyListsAreJSONArrays(t *testing.T) {
	mux := newTestMux(t, testServiceFakes{})

	for _, path := range []string{
		"/api/v1/assets",
		"/api/v1/findings",
		"/api/v1/priorities",
		"/api/v1/remediation-plans",
		"/api/v1/exceptions",
		"/api/v1/vulnerabilities",
		"/api/v1/verifications",
	} {
		rec := get(t, mux, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want %d", path, rec.Code, http.StatusOK)
		}
		if got := rec.Body.String(); got != "[]\n" {
			t.Errorf("%s: body = %q, want %q", path, got, "[]\n")
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type = %q, want application/json", path, ct)
		}
	}
}

func TestNewMux_AssetsReturnsData(t *testing.T) {
	a := &asset.Asset{ID: asset.NewID(), Hostname: "web-01"}
	mux := newTestMux(t, testServiceFakes{assets: assetsFake{items: []*asset.Asset{a}}})

	rec := get(t, mux, "/api/v1/assets")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body)
	}

	var got []asset.Asset
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(got) != 1 || got[0].Hostname != "web-01" {
		t.Errorf("got %+v, want one asset with hostname web-01", got)
	}
}

func TestNewMux_VulnerabilitiesReturnsData(t *testing.T) {
	v := &vulnerability.Vulnerability{ID: vulnerability.NewID(), Title: "Zabbix Agent 2 Heap Overflow", CVEID: "CVE-2021-36159"}
	mux := newTestMux(t, testServiceFakes{vulnerabilities: vulnerabilitiesFake{items: []*vulnerability.Vulnerability{v}}})

	rec := get(t, mux, "/api/v1/vulnerabilities")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body)
	}

	var got []vulnerability.Vulnerability
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(got) != 1 || got[0].CVEID != "CVE-2021-36159" {
		t.Errorf("got %+v, want one vulnerability with CVE-2021-36159", got)
	}
}

func TestNewMux_VerificationsReturnsData(t *testing.T) {
	v := &verification.Verification{ID: verification.NewID(), Method: verification.MethodScannerRescan, Result: verification.ResultPass}
	mux := newTestMux(t, testServiceFakes{verifications: verificationsFake{items: []*verification.Verification{v}}})

	rec := get(t, mux, "/api/v1/verifications")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body)
	}

	var got []verification.Verification
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(got) != 1 || got[0].Result != verification.ResultPass {
		t.Errorf("got %+v, want one passing verification", got)
	}
}

func TestNewMux_ApplicationErrorBecomes500(t *testing.T) {
	mux := newTestMux(t, testServiceFakes{
		findings: findingsFake{err: errors.New("application: list findings: boom")},
	})

	rec := get(t, mux, "/api/v1/findings")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if body["error"] != "application: list findings: boom" {
		t.Errorf(`error = %q, want "application: list findings: boom"`, body["error"])
	}
}

func TestNewMux_UnknownRouteIs404(t *testing.T) {
	mux := newTestMux(t, testServiceFakes{})

	rec := get(t, mux, "/api/v1/software")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (no ListSoftware endpoint exists)", rec.Code, http.StatusNotFound)
	}
}

func TestRequireScope_MissingAuthorizationHeaderIs401(t *testing.T) {
	mux := newTestMux(t, testServiceFakes{})

	rec := getAs(t, mux, "/api/v1/assets", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if body["error"] != errMissingBearerToken.Error() {
		t.Errorf("error = %q, want %q", body["error"], errMissingBearerToken.Error())
	}
}

func TestRequireScope_UnknownTokenIs401(t *testing.T) {
	mux := newTestMux(t, testServiceFakes{})

	rec := getAs(t, mux, "/api/v1/assets", "rf_this-token-does-not-exist")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if body["error"] != errInvalidToken.Error() {
		t.Errorf("error = %q, want %q", body["error"], errInvalidToken.Error())
	}
}

func TestRequireScope_WrongSchemeIs401(t *testing.T) {
	mux := newTestMux(t, testServiceFakes{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Basic "+testRawToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireScope_InsufficientScopeIs403(t *testing.T) {
	mux := newTestMux(t, testServiceFakes{})

	rec := getAs(t, mux, "/api/v1/assets", testRawTokenWrongScope)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if body["error"] != errInsufficientScope.Error() {
		t.Errorf("error = %q, want %q", body["error"], errInsufficientScope.Error())
	}
}

func TestRequireScope_PutsPrincipalInContext(t *testing.T) {
	var gotPrincipal *authn.Principal
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrincipal, _ = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	svc := newTestService(t, testServiceFakes{})
	handler := RequireScope(svc, authn.ScopeRead)(inner)

	rec := getAs(t, handler, "/", testRawToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotPrincipal == nil || gotPrincipal.ID != testPrincipalID {
		t.Errorf("PrincipalFromContext() = %+v, want principal %s", gotPrincipal, testPrincipalID)
	}
}
