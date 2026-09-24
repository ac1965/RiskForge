// Package verification holds the Verification entity (AGENTS.md §16): the
// confirmation that a remediated Finding is actually fixed.
//
// Verification is never conflated with Remediation (AGENTS.md §44
// Invariant 3): a completed remediation.Plan says a change was made, and
// only a Verification says whether that change actually worked. A
// Finding is never moved to StatusVerified without one (AGENTS.md §44
// Invariant 6), and an inconclusive Verification (e.g. the check couldn't
// run) is never treated as if the fix had failed (AGENTS.md §20A.6.1).
package verification
