package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// Stateful fakes for the write-endpoint tests: Save must actually
// persist so a later FindByID/Approve/etc. can see it, unlike
// api_test.go's static items/err fakes (which only need to satisfy the
// read-only list tests).

type statefulFindingsRepo struct {
	byID map[finding.ID]*finding.Finding
}

func newStatefulFindingsRepo() *statefulFindingsRepo {
	return &statefulFindingsRepo{byID: map[finding.ID]*finding.Finding{}}
}

func (r *statefulFindingsRepo) Save(_ context.Context, f *finding.Finding) error {
	r.byID[f.ID] = f
	return nil
}
func (r *statefulFindingsRepo) FindByID(_ context.Context, id finding.ID) (*finding.Finding, error) {
	return r.byID[id], nil
}
func (r *statefulFindingsRepo) FindByAssetAndVulnerability(context.Context, asset.ID, vulnerability.ID) (*finding.Finding, error) {
	return nil, nil
}
func (r *statefulFindingsRepo) List(context.Context) ([]*finding.Finding, error) {
	out := make([]*finding.Finding, 0, len(r.byID))
	for _, f := range r.byID {
		out = append(out, f)
	}
	return out, nil
}

type statefulExceptionsRepo struct {
	byID map[exception.ID]*exception.Exception
}

func newStatefulExceptionsRepo() *statefulExceptionsRepo {
	return &statefulExceptionsRepo{byID: map[exception.ID]*exception.Exception{}}
}

func (r *statefulExceptionsRepo) Save(_ context.Context, e *exception.Exception) error {
	r.byID[e.ID] = e
	return nil
}
func (r *statefulExceptionsRepo) FindByID(_ context.Context, id exception.ID) (*exception.Exception, error) {
	return r.byID[id], nil
}
func (r *statefulExceptionsRepo) List(context.Context) ([]*exception.Exception, error) {
	out := make([]*exception.Exception, 0, len(r.byID))
	for _, e := range r.byID {
		out = append(out, e)
	}
	return out, nil
}

func postJSON(t *testing.T, h http.Handler, rawToken, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request body: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	if rawToken != "" {
		req.Header.Set("Authorization", "Bearer "+rawToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestExceptionWorkflow_EndToEnd(t *testing.T) {
	findings := newStatefulFindingsRepo()
	f := &finding.Finding{ID: finding.NewID(), Status: finding.StatusOpen}
	findings.byID[f.ID] = f

	exceptions := newStatefulExceptionsRepo()
	mux := NewMux(newTestService(t, testServiceFakes{findingsRepo: findings, exceptionsRepo: exceptions}))

	// A requester-scoped token can create a request, but not decide one.
	createBody := map[string]string{
		"FindingID": string(f.ID),
		"Reason":    "compensating control in place",
		"ExpiresAt": time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
	}
	rec := postJSON(t, mux, testRawTokenExceptionRequester, "/api/v1/exceptions", createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want %d, body = %s", rec.Code, http.StatusCreated, rec.Body)
	}
	var created exception.Exception
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created exception: %v", err)
	}
	if created.RequestedBy != testExceptionRequesterName {
		t.Errorf("RequestedBy = %q, want %q (from the authenticated Principal, not client input)", created.RequestedBy, testExceptionRequesterName)
	}
	if created.Status != exception.StatusRequested {
		t.Errorf("Status = %q, want %q", created.Status, exception.StatusRequested)
	}

	// The requester's token cannot approve (wrong scope).
	rec = postJSON(t, mux, testRawTokenExceptionRequester, "/api/v1/exceptions/"+string(created.ID)+"/approve", map[string]string{"Reason": "ok"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("approve with requester token: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// The approver-scoped token can approve.
	rec = postJSON(t, mux, testRawTokenExceptionApprover, "/api/v1/exceptions/"+string(created.ID)+"/approve", map[string]string{"Reason": "accepted for this quarter"})
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body)
	}
	var approved exception.Exception
	if err := json.Unmarshal(rec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("unmarshal approved exception: %v", err)
	}
	if approved.Status != exception.StatusApproved || approved.ApprovedBy != testExceptionApproverName {
		t.Errorf("after approve: status=%q approvedBy=%q, want %q approved by %q", approved.Status, approved.ApprovedBy, exception.StatusApproved, testExceptionApproverName)
	}

	// Approving an already-approved exception is an invalid transition -> 409.
	rec = postJSON(t, mux, testRawTokenExceptionApprover, "/api/v1/exceptions/"+string(created.ID)+"/approve", map[string]string{"Reason": "again"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("double approve: status = %d, want %d, body = %s", rec.Code, http.StatusConflict, rec.Body)
	}

	// Revoking an approved exception succeeds.
	rec = postJSON(t, mux, testRawTokenExceptionApprover, "/api/v1/exceptions/"+string(created.ID)+"/revoke", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body)
	}
	var revoked exception.Exception
	if err := json.Unmarshal(rec.Body.Bytes(), &revoked); err != nil {
		t.Fatalf("unmarshal revoked exception: %v", err)
	}
	if revoked.Status != exception.StatusRevoked {
		t.Errorf("Status = %q, want %q", revoked.Status, exception.StatusRevoked)
	}
}

func TestRequestException_MissingRequiredFieldIs400(t *testing.T) {
	mux := NewMux(newTestService(t, testServiceFakes{findingsRepo: newStatefulFindingsRepo(), exceptionsRepo: newStatefulExceptionsRepo()}))

	rec := postJSON(t, mux, testRawTokenExceptionRequester, "/api/v1/exceptions", map[string]string{"Reason": "no finding id given"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body)
	}
}

func TestRequestException_UnknownFindingIsRejected(t *testing.T) {
	mux := NewMux(newTestService(t, testServiceFakes{findingsRepo: newStatefulFindingsRepo(), exceptionsRepo: newStatefulExceptionsRepo()}))

	body := map[string]string{
		"FindingID": string(finding.NewID()),
		"Reason":    "x",
		"ExpiresAt": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	rec := postJSON(t, mux, testRawTokenExceptionRequester, "/api/v1/exceptions", body)
	// finding-not-found in RequestException is not wrapped in
	// application.ErrNotFound (ADR 0014: only the *addressed* resource,
	// i.e. the Exception in approve/reject/expire/revoke, gets 404 here),
	// so this falls into the residual 400 bucket.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body)
	}
}

func TestApproveException_UnknownIDIs404(t *testing.T) {
	mux := NewMux(newTestService(t, testServiceFakes{findingsRepo: newStatefulFindingsRepo(), exceptionsRepo: newStatefulExceptionsRepo()}))

	rec := postJSON(t, mux, testRawTokenExceptionApprover, "/api/v1/exceptions/"+string(exception.NewID())+"/approve", map[string]string{"Reason": "x"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusNotFound, rec.Body)
	}
}

func TestExpireException_DefaultsReason(t *testing.T) {
	findings := newStatefulFindingsRepo()
	f := &finding.Finding{ID: finding.NewID(), Status: finding.StatusOpen}
	findings.byID[f.ID] = f
	exceptions := newStatefulExceptionsRepo()
	mux := NewMux(newTestService(t, testServiceFakes{findingsRepo: findings, exceptionsRepo: exceptions}))

	created := requestAndApprove(t, mux, f.ID)

	rec := postJSON(t, mux, testRawTokenExceptionApprover, "/api/v1/exceptions/"+string(created)+"/expire", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expire: status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body)
	}
	var expired exception.Exception
	if err := json.Unmarshal(rec.Body.Bytes(), &expired); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if expired.Status != exception.StatusExpired {
		t.Errorf("Status = %q, want %q", expired.Status, exception.StatusExpired)
	}
}

// requestAndApprove is a small helper for tests that need an already-
// approved Exception to act on next (expire, double-approve, etc.).
func requestAndApprove(t *testing.T, mux http.Handler, findingID finding.ID) exception.ID {
	t.Helper()
	body := map[string]string{
		"FindingID": string(findingID),
		"Reason":    "x",
		"ExpiresAt": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	rec := postJSON(t, mux, testRawTokenExceptionRequester, "/api/v1/exceptions", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: create exception: status = %d, body = %s", rec.Code, rec.Body)
	}
	var created exception.Exception
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("setup: unmarshal created exception: %v", err)
	}

	rec = postJSON(t, mux, testRawTokenExceptionApprover, "/api/v1/exceptions/"+string(created.ID)+"/approve", map[string]string{"Reason": "x"})
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: approve exception: status = %d, body = %s", rec.Code, rec.Body)
	}
	return created.ID
}
