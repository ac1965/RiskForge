// Package evidence holds the Evidence entity (AGENTS.md §17): the
// first-class, tamper-evident record backing a detection, a remediation
// execution, or a verification result.
//
// Evidence is never conflated with Finding (AGENTS.md §44 Invariant 4):
// Finding is the mutable fact that a vulnerability was detected, while
// Evidence is an immutable record supporting that fact or a later action.
// Evidence has no update method — only New. Once created it is never
// modified, only ever superseded by new Evidence (AGENTS.md §22, §47.10).
package evidence
