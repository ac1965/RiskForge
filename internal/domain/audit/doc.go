// Package audit holds the Entry entity (AGENTS.md §30): an immutable
// record of a significant operation, tracking at least who, what, when,
// why, before, and after.
//
// Entry has no update method — only New — for the same reason as
// evidence.Evidence: an audit trail that could be edited after the fact
// would defeat its purpose.
//
// Action is intentionally an open string, not a closed enum: AGENTS.md
// §20A.8 adds further actions (e.g. pownforge_import) in a later
// integration phase, and audit must be able to record those without a
// breaking change to this type.
package audit
