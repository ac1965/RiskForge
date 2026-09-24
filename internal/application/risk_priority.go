package application

import (
	"context"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/risk"
)

// AssessRisk is the assess_risk() Named API (AGENTS.md §26). It loads the
// Finding's Asset and Vulnerability, delegates scoring entirely to
// s.RiskEngine (AGENTS.md §8 — Application never computes a score
// itself), and records a risk_change audit.Entry (AGENTS.md §30).
func (s *Service) AssessRisk(ctx context.Context, findingID finding.ID) (*risk.Assessment, error) {
	f, a, v, err := s.loadFindingContext(ctx, findingID)
	if err != nil {
		return nil, err
	}

	previous, err := s.RiskAssessments.FindLatestByFinding(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("application: find latest risk assessment for finding %s: %w", findingID, err)
	}

	assessment, err := s.RiskEngine.Assess(risk.Input{Finding: f, Asset: a, Vulnerability: v})
	if err != nil {
		return nil, fmt.Errorf("application: assess risk for finding %s: %w", findingID, err)
	}
	if err := s.RiskAssessments.Save(ctx, assessment); err != nil {
		return nil, fmt.Errorf("application: save risk assessment %s: %w", assessment.ID, err)
	}

	before := ""
	if previous != nil {
		before = toJSON(previous)
	}
	entry, err := audit.New(audit.Params{
		Action:      audit.ActionRiskChange,
		Who:         "system",
		SubjectType: "finding",
		SubjectID:   string(findingID),
		What:        fmt.Sprintf("Assessed risk for finding %s: score %.1f (%s)", findingID, assessment.Score, assessment.Level),
		Why:         fmt.Sprintf("Automated risk assessment via policy %q v%s", assessment.PolicyName, assessment.PolicyVersion),
		Before:      before,
		After:       toJSON(assessment),
		OccurredAt:  assessment.AssessedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return assessment, nil
}

// CalculatePriority is the calculate_priority() Named API (AGENTS.md
// §26). It requires a RiskAssessment to already exist for the Finding
// (assess_risk must run first, matching the Risk -> Priority pipeline in
// AGENTS.md §24), delegates ranking entirely to s.PriorityEngine, and
// records a priority_change audit.Entry.
func (s *Service) CalculatePriority(ctx context.Context, findingID finding.ID) (*priority.Decision, error) {
	f, a, v, err := s.loadFindingContext(ctx, findingID)
	if err != nil {
		return nil, err
	}

	assessment, err := s.RiskAssessments.FindLatestByFinding(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("application: find latest risk assessment for finding %s: %w", findingID, err)
	}
	if assessment == nil {
		return nil, fmt.Errorf("application: no risk assessment found for finding %s; assess risk first", findingID)
	}

	previous, err := s.PriorityDecisions.FindLatestByFinding(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("application: find latest priority decision for finding %s: %w", findingID, err)
	}

	decision, err := s.PriorityEngine.Decide(priority.Input{
		Input:          risk.Input{Finding: f, Asset: a, Vulnerability: v},
		RiskAssessment: assessment,
	})
	if err != nil {
		return nil, fmt.Errorf("application: calculate priority for finding %s: %w", findingID, err)
	}
	if err := s.PriorityDecisions.Save(ctx, decision); err != nil {
		return nil, fmt.Errorf("application: save priority decision %s: %w", decision.ID, err)
	}

	before := ""
	if previous != nil {
		before = toJSON(previous)
	}
	entry, err := audit.New(audit.Params{
		Action:      audit.ActionPriorityChange,
		Who:         "system",
		SubjectType: "finding",
		SubjectID:   string(findingID),
		What:        fmt.Sprintf("Calculated priority for finding %s: rank %.1f (%s)", findingID, decision.Rank, decision.Level),
		Why:         fmt.Sprintf("Automated priority decision via policy %q v%s", decision.PolicyName, decision.PolicyVersion),
		Before:      before,
		After:       toJSON(decision),
		OccurredAt:  decision.DecidedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("application: build audit entry: %w", err)
	}
	if err := s.Audit.Save(ctx, entry); err != nil {
		return nil, fmt.Errorf("application: save audit entry: %w", err)
	}

	return decision, nil
}
