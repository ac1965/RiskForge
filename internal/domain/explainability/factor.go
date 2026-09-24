// Package explainability holds the shared building block for
// human-readable score explanations (AGENTS.md §40): a Risk Score or
// Priority Rank must never be shown without the Factors and Reasons
// behind it.
package explainability

import "fmt"

// Factor is a single named contributor to a score, e.g. "CVSS 9.8" or
// "CISA KEV listed".
type Factor struct {
	Name   string
	Value  string
	Reason string
}

// Validate reports whether the factor is usable for display: Name and
// Reason must be present so the score can always be explained.
func (f Factor) Validate() error {
	if f.Name == "" {
		return fmt.Errorf("explainability: factor name is required")
	}
	if f.Reason == "" {
		return fmt.Errorf("explainability: factor %q is missing a reason", f.Name)
	}
	return nil
}
