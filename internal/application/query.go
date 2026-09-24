package application

import (
	"context"
	"fmt"
	"sort"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/remediation"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// This file holds read-only lookups the CLI's `list`/`show`/`inspect`
// commands (AGENTS.md §27) need beyond the write-oriented Named APIs in
// §26. They are thin, unaudited passthroughs to the repository ports.

// ListAssets returns every Asset, for `riskforge asset list`.
func (s *Service) ListAssets(ctx context.Context) ([]*asset.Asset, error) {
	return s.Assets.List(ctx)
}

// GetAsset returns the Asset with the given id, for `riskforge asset
// inspect`.
func (s *Service) GetAsset(ctx context.Context, id asset.ID) (*asset.Asset, error) {
	a, err := s.Assets.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("application: find asset %s: %w", id, err)
	}
	if a == nil {
		return nil, fmt.Errorf("application: asset %s not found", id)
	}
	return a, nil
}

// GetVulnerability returns the Vulnerability with the given id.
func (s *Service) GetVulnerability(ctx context.Context, id vulnerability.ID) (*vulnerability.Vulnerability, error) {
	v, err := s.Vulnerabilities.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("application: find vulnerability %s: %w", id, err)
	}
	if v == nil {
		return nil, fmt.Errorf("application: vulnerability %s not found", id)
	}
	return v, nil
}

// RecordVulnerability validates and saves a Vulnerability. Unlike
// DiscoverAssets/CorrelateFindings, this is not idempotent by a natural
// key: deduplicating by CVE ID against live threat-intel feeds is the
// Data Source Adapter's job (AGENTS.md §19), which is Phase 5 scope. This
// exists so a Vulnerability can be entered at all before that pipeline is
// built.
func (s *Service) RecordVulnerability(ctx context.Context, p vulnerability.Params) (*vulnerability.Vulnerability, error) {
	v, err := vulnerability.New(p)
	if err != nil {
		return nil, fmt.Errorf("application: record vulnerability: %w", err)
	}
	if err := s.Vulnerabilities.Save(ctx, v); err != nil {
		return nil, fmt.Errorf("application: save vulnerability %s: %w", v.ID, err)
	}
	return v, nil
}

// ListFindings returns every Finding, for `riskforge finding list`.
func (s *Service) ListFindings(ctx context.Context) ([]*finding.Finding, error) {
	return s.Findings.List(ctx)
}

// GetFinding returns the Finding with the given id, for `riskforge
// finding show`.
func (s *Service) GetFinding(ctx context.Context, id finding.ID) (*finding.Finding, error) {
	f, err := s.Findings.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("application: find finding %s: %w", id, err)
	}
	if f == nil {
		return nil, fmt.Errorf("application: finding %s not found", id)
	}
	return f, nil
}

// ListPriorities returns the latest PriorityDecision for every Finding
// that has one, ranked highest Rank first, for `riskforge priority list`.
func (s *Service) ListPriorities(ctx context.Context) ([]*priority.Decision, error) {
	decisions, err := s.PriorityDecisions.ListLatest(ctx)
	if err != nil {
		return nil, fmt.Errorf("application: list priority decisions: %w", err)
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].Rank > decisions[j].Rank })
	return decisions, nil
}

// ListRemediationPlans returns every RemediationPlan, for `riskforge
// remediation list`.
func (s *Service) ListRemediationPlans(ctx context.Context) ([]*remediation.Plan, error) {
	return s.RemediationPlans.List(ctx)
}

// GetRemediationPlan returns the RemediationPlan with the given id.
func (s *Service) GetRemediationPlan(ctx context.Context, id remediation.ID) (*remediation.Plan, error) {
	p, err := s.RemediationPlans.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("application: find remediation plan %s: %w", id, err)
	}
	if p == nil {
		return nil, fmt.Errorf("application: remediation plan %s not found", id)
	}
	return p, nil
}

// GetEvidence returns the Evidence with the given id, for `riskforge
// evidence show`.
func (s *Service) GetEvidence(ctx context.Context, id evidence.ID) (*evidence.Evidence, error) {
	e, err := s.Evidence.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("application: find evidence %s: %w", id, err)
	}
	if e == nil {
		return nil, fmt.Errorf("application: evidence %s not found", id)
	}
	return e, nil
}

// ListExceptions returns every Exception, for `riskforge exception list`.
func (s *Service) ListExceptions(ctx context.Context) ([]*exception.Exception, error) {
	return s.Exceptions.List(ctx)
}

// GetException returns the Exception with the given id.
func (s *Service) GetException(ctx context.Context, id exception.ID) (*exception.Exception, error) {
	e, err := s.Exceptions.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("application: find exception %s: %w", id, err)
	}
	if e == nil {
		return nil, fmt.Errorf("application: exception %s not found", id)
	}
	return e, nil
}
