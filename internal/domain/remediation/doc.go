// Package remediation holds the RemediationPlan entity (AGENTS.md §13,
// §14): a proposed, approved, and executed change addressing a Finding.
//
// Remediation is never conflated with Verification (AGENTS.md §44
// Invariant 3): completing a Plan means the change was made, not that it
// was confirmed effective. A completed Plan's Finding still requires a
// separate Verification before it can be considered fully resolved
// (AGENTS.md §16).
//
// Automatic remediation gating (AGENTS.md §15's auto_remediation_policy)
// is deferred to the Phase 4 Policy Engine (§23, §45); this package only
// provides the structural safety property that matters now: a Plan can
// never move to InProgress without first passing through Approved.
package remediation
