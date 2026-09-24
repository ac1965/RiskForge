# 0007. Exception, Policy, and Audit domain model

## Status

Accepted

## Context

Phase 4 (AGENTS.md §45) covers three areas — Exception (§18), Policy
(§23), and Audit (§30) — that differ a lot in how concretely AGENTS.md
specifies them:

- §18 gives Exception a full field list and explicit behavioral rules (no
  permanent exceptions by default, expired exceptions go up for
  re-evaluation).
- §30 gives Audit a full field list too (who/what/when/why/before/after)
  plus a fixed initial list of Actions, explicitly extended later by
  §20A.8.
- §23 is architectural guidance ("don't hardcode policy logic, use a
  Policy Engine") rather than a schema. Two of its named policies
  (risk_policy, priority_policy) already exist as pluggable interfaces
  (`risk.Policy`, `priority.Policy`, Phase 2, ADR 0002). One
  (auto_remediation_policy) has an explicit field list in §15 and was
  deliberately deferred here from Phase 3 (ADR 0003). The rest
  (remediation_policy, exception_policy, verification_policy) have no
  field list anywhere in AGENTS.md.
- §29's explicit list of database tables to keep separate does not
  include a "policies" table, unlike every other Phase 1–4 entity.

This means Policy cannot be implemented the same way as Exception and
Audit: there's no single schema to model. Building a generic, persisted,
versioned "Policy document" aggregate (id/name/version/status/config
blob/activation workflow) would be inventing structure §29 doesn't ask
for, and would drift into configuration-management infrastructure rather
than domain modeling.

## Decision

- **Exception** (`internal/domain/exception`) implements the full §18
  field list plus a Status state machine (Requested → Approved/Rejected;
  Approved → Expired/Revoked). `Exception.ImpliedFindingStatus()` mirrors
  the pattern from remediation.Plan and verification.Verification
  (ADR 0003): Approved implies `finding.StatusAccepted`, Expired/Revoked
  imply `finding.StatusReopened`, and Requested/Rejected imply no
  transition — a request that was never approved never moved the Finding.
  A companion `exception.Policy{MaxDuration}` enforces "永久的な例外をデフォ
  ルトにしない" as an organizational limit, separate from `New`'s bare
  requirement that `ExpiresAt` be set at all.
- **Audit** (`internal/domain/audit`) implements the §30 field list
  exactly, plus `SubjectType`/`SubjectID` (generic string references, so
  this package never needs to import every other domain package to name
  what it's auditing). `Action` stays a plain string with the §30 actions
  as named constants, not a closed enum, because §20A.8 already commits
  to adding more (pownforge_import, etc.) in a later phase. Like
  `evidence.Evidence`, `Entry` has no update method.
- **Policy** (`internal/domain/policy`) is scoped to exactly what §23
  left unimplemented and concrete: `AutoRemediationPolicy` (§15's fields:
  AllowAutomaticExecution, AllowedAssetTypes, AllowedEnvironments,
  AllowedActionTypes, MaintenanceWindow, RollbackRequired), with a
  zero-value that denies everything — the same safe-by-default property
  ADR 0003 already established via remediation.Plan's state machine, now
  also available as an explicit, inspectable configuration object. A
  `Kind` enum names the six policies from §23 for classification (e.g. an
  audit.Entry's SubjectType), without requiring every policy to be
  represented as data in this package.
- Explicitly **not** built: a generic persisted Policy aggregate with its
  own ID/version/status/activation-workflow, and concrete
  `remediation_policy` / `exception_policy` / `verification_policy` data
  structures beyond what already exists (the remediation approval gate,
  `exception.Policy`, and verification's method/result validation). If a
  real requirement for storing and versioning arbitrary policy
  configuration emerges, it should be scoped and recorded as its own ADR
  rather than folded in here speculatively (AGENTS.md §47.11).

## Consequences

- Application-layer code that needs to gate an automatic remediation
  attempt loads an `AutoRemediationPolicy` value (from wherever
  configuration ends up living — out of scope here) and calls
  `Allows(...)` before ever calling `remediation.Plan.Approve`; it cannot
  use this to skip `Plan`'s own state machine.
- `exception.Policy` and `priority.SLAPolicy` (Phase 2) follow the same
  shape deliberately: a small value type with a `Validate`/`Deadline`
  method, not a persisted entity — consistent handling for "policy as
  data" across phases.
- If Phase 5 needs a real config-driven Policy Engine (loading named,
  versioned policies from a store), it can be added as new infrastructure
  that constructs these same types (`risk.Policy`, `priority.Policy`,
  `AutoRemediationPolicy`, `exception.Policy`) from stored configuration,
  without changing any of the Engine or entity code built in Phases 2–4.
