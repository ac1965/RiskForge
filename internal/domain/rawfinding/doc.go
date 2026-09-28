// Package rawfinding holds the RawFinding entity and the classification
// step of the Scanner pipeline (AGENTS.md §20, §20A): Scanner -> RawFinding
// -> Normalizer -> Matcher -> Finding.
//
// RawFinding is a Scanner's raw, not-yet-correlated observation -- distinct
// from Finding (which asserts a specific Vulnerability was detected on a
// specific Asset, AGENTS.md §44 Invariant 1). A RawFinding may describe a
// vulnerability RiskForge cannot yet identify, or may turn out not to
// warrant a Vulnerability/Finding at all; it is never written directly to
// the domain model Finding represents.
//
// Classify implements only the AGENTS.md §20A.2 three-way split (known
// Vulnerability / CVE-less Vulnerability / unclassified-and-held). It does
// not look anything up in a repository -- deciding whether an extracted CVE
// ID actually matches a known Vulnerability record is the Matcher's job
// (AGENTS.md §20), not the Normalizer's, and is intentionally out of scope
// here (see docs/adr/0015-rawfinding-domain-model.md "対象外").
package rawfinding
