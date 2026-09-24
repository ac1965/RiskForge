// Package priority implements the Priority Engine (AGENTS.md §12): it
// decides what to remediate first, which is a distinct question from how
// much risk a Finding carries (AGENTS.md §44 Invariant 2: Risk !=
// Priority).
//
// Two Findings with the same risk.Assessment.Score can still be
// prioritized differently — e.g. a production, internet-facing,
// business-critical asset is generally handled before an otherwise
// identical finding on a low-criticality internal asset (AGENTS.md §12).
package priority
