package application

import (
	"context"
	"errors"

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

// The fakes in this file are minimal in-memory stand-ins for the ports in
// ports.go, used only by this package's tests. They are not a real
// Infrastructure implementation (no persistence, no concurrency safety).

type assetRepo struct {
	byID       map[asset.ID]*asset.Asset
	byHostname map[string]asset.ID
}

func newAssetRepo() *assetRepo {
	return &assetRepo{byID: map[asset.ID]*asset.Asset{}, byHostname: map[string]asset.ID{}}
}

func (r *assetRepo) Save(_ context.Context, a *asset.Asset) error {
	cp := *a
	r.byID[a.ID] = &cp
	r.byHostname[a.Hostname] = a.ID
	return nil
}

func (r *assetRepo) FindByID(_ context.Context, id asset.ID) (*asset.Asset, error) {
	a, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *a
	return &cp, nil
}

func (r *assetRepo) List(_ context.Context) ([]*asset.Asset, error) {
	out := make([]*asset.Asset, 0, len(r.byID))
	for _, a := range r.byID {
		cp := *a
		out = append(out, &cp)
	}
	return out, nil
}

func (r *assetRepo) FindByHostname(_ context.Context, hostname string) (*asset.Asset, error) {
	id, ok := r.byHostname[hostname]
	if !ok {
		return nil, nil
	}
	return r.FindByID(context.Background(), id)
}

type softwareRepo struct {
	byID map[software.ID]*software.Installation
}

func newSoftwareRepo() *softwareRepo {
	return &softwareRepo{byID: map[software.ID]*software.Installation{}}
}

func (r *softwareRepo) Save(_ context.Context, i *software.Installation) error {
	cp := *i
	r.byID[i.ID] = &cp
	return nil
}

func (r *softwareRepo) FindByNaturalKey(_ context.Context, assetID asset.ID, vendor, product, version string) (*software.Installation, error) {
	for _, i := range r.byID {
		if i.AssetID == assetID && i.Vendor == vendor && i.Product == product && i.Version == version {
			cp := *i
			return &cp, nil
		}
	}
	return nil, nil
}

type vulnerabilityRepo struct {
	byID map[vulnerability.ID]*vulnerability.Vulnerability
}

func newVulnerabilityRepo() *vulnerabilityRepo {
	return &vulnerabilityRepo{byID: map[vulnerability.ID]*vulnerability.Vulnerability{}}
}

func (r *vulnerabilityRepo) Save(_ context.Context, v *vulnerability.Vulnerability) error {
	cp := *v
	r.byID[v.ID] = &cp
	return nil
}

func (r *vulnerabilityRepo) FindByID(_ context.Context, id vulnerability.ID) (*vulnerability.Vulnerability, error) {
	v, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *v
	return &cp, nil
}

func (r *vulnerabilityRepo) FindByCVE(_ context.Context, cveID string) (*vulnerability.Vulnerability, error) {
	for _, v := range r.byID {
		if v.CVEID == cveID {
			cp := *v
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *vulnerabilityRepo) FindByProvenanceSourceID(_ context.Context, source, sourceID string) (*vulnerability.Vulnerability, error) {
	for _, v := range r.byID {
		if v.Provenance.Source == source && v.Provenance.SourceID == sourceID {
			cp := *v
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *vulnerabilityRepo) List(_ context.Context) ([]*vulnerability.Vulnerability, error) {
	out := make([]*vulnerability.Vulnerability, 0, len(r.byID))
	for _, v := range r.byID {
		cp := *v
		out = append(out, &cp)
	}
	return out, nil
}

type rawFindingRepo struct {
	byID map[rawfinding.ID]*rawfinding.RawFinding
}

func newRawFindingRepo() *rawFindingRepo {
	return &rawFindingRepo{byID: map[rawfinding.ID]*rawfinding.RawFinding{}}
}

func (r *rawFindingRepo) Save(_ context.Context, rf *rawfinding.RawFinding) error {
	cp := *rf
	r.byID[rf.ID] = &cp
	return nil
}

func (r *rawFindingRepo) FindByID(_ context.Context, id rawfinding.ID) (*rawfinding.RawFinding, error) {
	rf, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *rf
	return &cp, nil
}

func (r *rawFindingRepo) List(_ context.Context) ([]*rawfinding.RawFinding, error) {
	out := make([]*rawfinding.RawFinding, 0, len(r.byID))
	for _, rf := range r.byID {
		cp := *rf
		out = append(out, &cp)
	}
	return out, nil
}

type findingRepo struct {
	byID map[finding.ID]*finding.Finding
}

func newFindingRepo() *findingRepo {
	return &findingRepo{byID: map[finding.ID]*finding.Finding{}}
}

func (r *findingRepo) Save(_ context.Context, f *finding.Finding) error {
	cp := *f
	r.byID[f.ID] = &cp
	return nil
}

func (r *findingRepo) FindByID(_ context.Context, id finding.ID) (*finding.Finding, error) {
	f, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *f
	return &cp, nil
}

func (r *findingRepo) FindByAssetAndVulnerability(_ context.Context, assetID asset.ID, vulnID vulnerability.ID) (*finding.Finding, error) {
	for _, f := range r.byID {
		if f.AssetID == assetID && f.VulnerabilityID == vulnID {
			cp := *f
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *findingRepo) List(_ context.Context) ([]*finding.Finding, error) {
	out := make([]*finding.Finding, 0, len(r.byID))
	for _, f := range r.byID {
		cp := *f
		out = append(out, &cp)
	}
	return out, nil
}

type riskAssessmentRepo struct {
	byFinding map[finding.ID]*risk.Assessment
}

func newRiskAssessmentRepo() *riskAssessmentRepo {
	return &riskAssessmentRepo{byFinding: map[finding.ID]*risk.Assessment{}}
}

func (r *riskAssessmentRepo) Save(_ context.Context, a *risk.Assessment) error {
	cp := *a
	r.byFinding[a.FindingID] = &cp
	return nil
}

func (r *riskAssessmentRepo) FindLatestByFinding(_ context.Context, findingID finding.ID) (*risk.Assessment, error) {
	a, ok := r.byFinding[findingID]
	if !ok {
		return nil, nil
	}
	cp := *a
	return &cp, nil
}

type priorityDecisionRepo struct {
	byFinding map[finding.ID]*priority.Decision
}

func newPriorityDecisionRepo() *priorityDecisionRepo {
	return &priorityDecisionRepo{byFinding: map[finding.ID]*priority.Decision{}}
}

func (r *priorityDecisionRepo) Save(_ context.Context, d *priority.Decision) error {
	cp := *d
	r.byFinding[d.FindingID] = &cp
	return nil
}

func (r *priorityDecisionRepo) FindLatestByFinding(_ context.Context, findingID finding.ID) (*priority.Decision, error) {
	d, ok := r.byFinding[findingID]
	if !ok {
		return nil, nil
	}
	cp := *d
	return &cp, nil
}

func (r *priorityDecisionRepo) ListLatest(_ context.Context) ([]*priority.Decision, error) {
	out := make([]*priority.Decision, 0, len(r.byFinding))
	for _, d := range r.byFinding {
		cp := *d
		out = append(out, &cp)
	}
	return out, nil
}

type remediationPlanRepo struct {
	byID map[remediation.ID]*remediation.Plan
}

func newRemediationPlanRepo() *remediationPlanRepo {
	return &remediationPlanRepo{byID: map[remediation.ID]*remediation.Plan{}}
}

func (r *remediationPlanRepo) Save(_ context.Context, p *remediation.Plan) error {
	cp := *p
	r.byID[p.ID] = &cp
	return nil
}

func (r *remediationPlanRepo) FindByID(_ context.Context, id remediation.ID) (*remediation.Plan, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

func (r *remediationPlanRepo) List(_ context.Context) ([]*remediation.Plan, error) {
	out := make([]*remediation.Plan, 0, len(r.byID))
	for _, p := range r.byID {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

type verificationRepo struct {
	saved []*verification.Verification
}

func newVerificationRepo() *verificationRepo {
	return &verificationRepo{}
}

func (r *verificationRepo) Save(_ context.Context, v *verification.Verification) error {
	r.saved = append(r.saved, v)
	return nil
}

func (r *verificationRepo) List(_ context.Context) ([]*verification.Verification, error) {
	out := make([]*verification.Verification, len(r.saved))
	copy(out, r.saved)
	return out, nil
}

type evidenceRepo struct {
	byID map[evidence.ID]*evidence.Evidence
}

func newEvidenceRepo() *evidenceRepo {
	return &evidenceRepo{byID: map[evidence.ID]*evidence.Evidence{}}
}

func (r *evidenceRepo) Save(_ context.Context, e *evidence.Evidence) error {
	cp := *e
	r.byID[e.ID] = &cp
	return nil
}

func (r *evidenceRepo) FindByID(_ context.Context, id evidence.ID) (*evidence.Evidence, error) {
	e, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *e
	return &cp, nil
}

type exceptionRepo struct {
	byID map[exception.ID]*exception.Exception
}

func newExceptionRepo() *exceptionRepo {
	return &exceptionRepo{byID: map[exception.ID]*exception.Exception{}}
}

func (r *exceptionRepo) Save(_ context.Context, e *exception.Exception) error {
	cp := *e
	r.byID[e.ID] = &cp
	return nil
}

func (r *exceptionRepo) FindByID(_ context.Context, id exception.ID) (*exception.Exception, error) {
	e, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *e
	return &cp, nil
}

func (r *exceptionRepo) List(_ context.Context) ([]*exception.Exception, error) {
	out := make([]*exception.Exception, 0, len(r.byID))
	for _, e := range r.byID {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

type auditRepo struct {
	saved []*audit.Entry
}

func newAuditRepo() *auditRepo {
	return &auditRepo{}
}

func (r *auditRepo) Save(_ context.Context, e *audit.Entry) error {
	r.saved = append(r.saved, e)
	return nil
}

type principalRepo struct {
	byID   map[authn.PrincipalID]*authn.Principal
	byName map[string]authn.PrincipalID
}

func newPrincipalRepo() *principalRepo {
	return &principalRepo{byID: map[authn.PrincipalID]*authn.Principal{}, byName: map[string]authn.PrincipalID{}}
}

func (r *principalRepo) Save(_ context.Context, p *authn.Principal) error {
	cp := *p
	r.byID[p.ID] = &cp
	r.byName[p.Name] = p.ID
	return nil
}

func (r *principalRepo) FindByID(_ context.Context, id authn.PrincipalID) (*authn.Principal, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

func (r *principalRepo) FindByName(_ context.Context, name string) (*authn.Principal, error) {
	id, ok := r.byName[name]
	if !ok {
		return nil, nil
	}
	return r.FindByID(context.Background(), id)
}

type apiTokenRepo struct {
	byID        map[authn.TokenID]*authn.APIToken
	byTokenHash map[string]authn.TokenID
}

func newAPITokenRepo() *apiTokenRepo {
	return &apiTokenRepo{byID: map[authn.TokenID]*authn.APIToken{}, byTokenHash: map[string]authn.TokenID{}}
}

func (r *apiTokenRepo) Save(_ context.Context, t *authn.APIToken) error {
	cp := *t
	r.byID[t.ID] = &cp
	r.byTokenHash[t.TokenHash] = t.ID
	return nil
}

func (r *apiTokenRepo) FindByID(_ context.Context, id authn.TokenID) (*authn.APIToken, error) {
	t, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *t
	return &cp, nil
}

func (r *apiTokenRepo) FindByTokenHash(_ context.Context, hash string) (*authn.APIToken, error) {
	id, ok := r.byTokenHash[hash]
	if !ok {
		return nil, nil
	}
	return r.FindByID(context.Background(), id)
}

func (r *apiTokenRepo) List(_ context.Context) ([]*authn.APIToken, error) {
	out := make([]*authn.APIToken, 0, len(r.byID))
	for _, t := range r.byID {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

// succeedingExecutor is a RemediationExecutor that always succeeds.
type succeedingExecutor struct{}

func (succeedingExecutor) Execute(context.Context, *remediation.Plan, remediation.DryRunInput) error {
	return nil
}

// failingExecutor is a RemediationExecutor that always fails.
type failingExecutor struct{}

func (failingExecutor) Execute(context.Context, *remediation.Plan, remediation.DryRunInput) error {
	return errors.New("simulated execution failure")
}
