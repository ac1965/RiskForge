// Package policy holds the policy configuration objects named in
// AGENTS.md §23 that don't already exist elsewhere as pluggable engine
// interfaces.
//
// risk_policy and priority_policy are already realized as risk.Policy and
// priority.Policy (Phase 2): scoring logic must be pluggable code, not
// just data, so those stay interfaces in their own packages. Kind exists
// here so other kinds of policy can still be named and classified the
// same way (e.g. for audit.Entry.SubjectType).
//
// AutoRemediationPolicy is the one policy in AGENTS.md with an explicit
// field list (§15) that had not been implemented yet — it was
// deliberately deferred from Phase 3 (see docs/adr/0003-remediation-safety.md)
// to land here instead of being hardcoded into remediation.Engine.
package policy
