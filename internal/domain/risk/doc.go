// Package risk implements the Risk Engine (AGENTS.md §8): it turns a
// Finding, its Asset, and its Vulnerability into a RiskAssessment.
//
// Risk is explicitly not CVSS, and not a fixed multiplication of factors
// (AGENTS.md §8, §44 Invariant 5). The Engine composes independent
// providers (severity, exploitability, asset criticality, exposure,
// business impact) and delegates the actual scoring to a pluggable
// Policy, so the scoring logic is never hardcoded into the Engine itself.
package risk
