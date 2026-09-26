package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
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

type vulnerabilitiesFake struct{}

func (vulnerabilitiesFake) Save(context.Context, *vulnerability.Vulnerability) error { return nil }
func (vulnerabilitiesFake) FindByID(context.Context, vulnerability.ID) (*vulnerability.Vulnerability, error) {
	return nil, nil
}

type riskAssessmentsFake struct{}

func (riskAssessmentsFake) Save(context.Context, *risk.Assessment) error { return nil }
func (riskAssessmentsFake) FindLatestByFinding(context.Context, finding.ID) (*risk.Assessment, error) {
	return nil, nil
}

type verificationsFake struct{}

func (verificationsFake) Save(context.Context, *verification.Verification) error { return nil }

type evidenceFake struct{}

func (evidenceFake) Save(context.Context, *evidence.Evidence) error { return nil }
func (evidenceFake) FindByID(context.Context, evidence.ID) (*evidence.Evidence, error) {
	return nil, nil
}

type auditFake struct{}

func (auditFake) Save(context.Context, *audit.Entry) error { return nil }

// testServiceFakes bundles the five fakes this package's tests actually
// configure per test case.
type testServiceFakes struct {
	assets            assetsFake
	findings          findingsFake
	priorityDecisions priorityDecisionsFake
	remediationPlans  remediationPlansFake
	exceptions        exceptionsFake
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

	svc, err := application.NewService(application.Service{
		Assets:            f.assets,
		Software:          softwareFake{},
		Vulnerabilities:   vulnerabilitiesFake{},
		Findings:          f.findings,
		RiskAssessments:   riskAssessmentsFake{},
		PriorityDecisions: f.priorityDecisions,
		RemediationPlans:  f.remediationPlans,
		Verifications:     verificationsFake{},
		Evidence:          evidenceFake{},
		Exceptions:        f.exceptions,
		Audit:             auditFake{},
		RiskEngine:        riskEngine,
		PriorityEngine:    priorityEngine,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	return svc
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestNewMux_EmptyListsAreJSONArrays verifies every endpoint returns `[]`
// (never `null`) when the underlying list is empty, matching ADR 0011's
// "the response is the resource array itself".
func TestNewMux_EmptyListsAreJSONArrays(t *testing.T) {
	mux := NewMux(newTestService(t, testServiceFakes{}))

	for _, path := range []string{
		"/api/v1/assets",
		"/api/v1/findings",
		"/api/v1/priorities",
		"/api/v1/remediation-plans",
		"/api/v1/exceptions",
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
	mux := NewMux(newTestService(t, testServiceFakes{assets: assetsFake{items: []*asset.Asset{a}}}))

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

func TestNewMux_ApplicationErrorBecomes500(t *testing.T) {
	mux := NewMux(newTestService(t, testServiceFakes{
		findings: findingsFake{err: errors.New("application: list findings: boom")},
	}))

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
	mux := NewMux(newTestService(t, testServiceFakes{}))

	rec := get(t, mux, "/api/v1/vulnerabilities")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (ADR 0011 scopes this PR to five endpoints only)", rec.Code, http.StatusNotFound)
	}
}
