# 0003. Remediation and Verification safety model

## Status

Accepted

## Context

AGENTS.md §13–§16 and §44 require several safety properties around fixing
a Finding:

- Automatic remediation must be disabled by default (§15, §47.7).
- `accept_risk` must never be treated as a successful remediation (§13).
- Every remediation action should support a Dry Run and, where possible, a
  Rollback, and state clearly when it cannot be rolled back (§33, §34).
- Remediation and Verification are distinct entities (§44 Invariant 3):
  completing a remediation.Plan means a change was made, not that it was
  confirmed effective.
- A Verification that could not run (e.g. the asset was unreachable) must
  not be treated as if the vulnerability were still present (§20A.6.1).

The general, configuration-driven Policy Engine (§23) — including the
`auto_remediation_policy` described in §15 — is Phase 4 work (§45). Phase
3 needs the underlying domain entities to make these properties hold
without waiting for that later engine.

## Decision

- `remediation.Plan`'s status transitions (`internal/domain/remediation/status.go`)
  disallow `StatusProposed -> StatusInProgress` directly: a plan must pass
  through `StatusApproved` (or `StatusScheduled`) first. This is what
  actually enforces "automatic remediation is disabled by default" at the
  domain level — there is no code path that skips approval, regardless of
  what any future policy configuration says.
- `remediation.Rollback` is a struct (`Capable bool`, `Plan string`,
  `Reason string`) rather than the single free-text `rollback_plan` field
  literally listed in §14. `Validate()` requires `Plan` when `Capable` is
  true and `Reason` when it is false, so "this action cannot be rolled
  back" is a structured fact, not something that has to be inferred from
  an empty string (§34).
- `Plan.DryRun` returns a `DryRunReport` (target asset, finding, action,
  planned change, rollback) and performs no OS command execution itself —
  producing the preview is the only thing it does (§25, §33). Actually
  executing a remediation action (the `validation → structured command →
  allowlist → execution` pipeline in §32) is an infrastructure-layer
  concern for a later phase.
- `Plan.ImpliedFindingStatus()` returns `finding.StatusAccepted` for
  `ActionAcceptRisk` and `finding.StatusRemediated` for every other action
  type, but never calls `finding.TransitionTo` itself — Plan holds a
  `FindingID`, not a live `*Finding`, so it cannot mutate another
  aggregate directly. This keeps Invariant 3 intact structurally: even a
  non-accept_risk plan's implied `StatusRemediated` still has to pass
  through `Finding.TransitionTo`, whose own transition table (from Phase
  1, ADR 0001) still refuses to go straight to `StatusVerified`.
- `verification.Verification.ImpliedFindingStatus()` mirrors this pattern:
  `ResultPass` implies `StatusVerified`, `ResultFail` implies
  `StatusReopened`, and `ResultInconclusive` implies no transition at all
  (`apply=false`), directly encoding §20A.6.1.
- `AutoRemediationPolicy` (the `require_approval` /
  `allowed_asset_types` / ... object from §15) is deliberately **not**
  implemented in Phase 3. The approval gate above already gives the
  required safety property; the configurable policy object belongs with
  the rest of the Policy Engine in Phase 4 (§23, §45), consistent with
  ADR 0002 deferring Risk/Priority's config-driven Policy the same way.

## Consequences

- Any future "auto-approve and auto-execute" automation (Phase 5) has to
  go through `Plan.Approve()` before `Plan.Start()` can succeed — it
  cannot bypass the domain's own state machine, only decide *when* to
  call `Approve` on the system's behalf.
- Application-layer code (not yet implemented) is responsible for reading
  `ImpliedFindingStatus()` from a completed Plan or a recorded
  Verification and calling `Finding.TransitionTo` with it — the domain
  layer exposes the mapping but does not perform cross-aggregate writes.
