// Package application exposes the Named Domain APIs (AGENTS.md §26) that the
// CLI and API layers call — e.g. DiscoverAssets, InventoryAsset,
// CorrelateFindings, AssessRisk, CalculatePriority, CreateRemediationPlan,
// ExecuteRemediation, VerifyRemediation, RecordEvidence.
//
// The CLI and API layers must not reach into internal/domain directly
// (AGENTS.md §25 Layering, §26).
package application
