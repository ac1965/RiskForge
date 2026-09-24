# 0008. Application layer: Named APIs and ports

## Status

Accepted

## Context

AGENTS.md §26 requires the CLI and API layers to call a set of Named
Domain APIs rather than reaching into `internal/domain` directly, and
lists nine examples: `discover_assets`, `inventory_asset`,
`correlate_findings`, `assess_risk`, `calculate_priority`,
`create_remediation_plan`, `execute_remediation`, `verify_remediation`,
`record_evidence`. Implementing these requires persistence, but
`internal/infrastructure/postgres` does not exist yet, and §25's layering
rule (`UI -> Application -> Domain -> Infrastructure`) means Application
cannot import a database driver directly.

Three things had to be decided beyond a literal reading of §26:

1. What defines the ports (repository interfaces) between Application and
   the not-yet-built Infrastructure layer.
2. `§26`'s list omits an approval step for Remediation and any entry
   points for Exception (Phase 4) at all, but both are unusable without
   one.
3. `§30` names exactly which operations must produce an audit.Entry, and
   that list is narrower than "every Named API call".

## Decision

- **Ports live in `internal/application/ports.go`**, one repository
  interface per aggregate (`AssetRepository`, `FindingRepository`, ...),
  each with `Save` plus whatever lookup the aggregate's idempotency rule
  needs. A "not found" lookup returns `(nil, nil)`; callers check for a
  nil result rather than a sentinel error. `RemediationExecutor` is a
  separate port for the actual infrastructure-level change a Plan
  describes (AGENTS.md §31, §32's validated/structured/allowlisted
  command pipeline) — no implementation exists yet, Application only
  defines the seam. `Service` (`service.go`) holds every port plus
  `risk.Engine`/`priority.Engine`, constructed once via `NewService`,
  which validates every field is set.
- **Idempotency keys (AGENTS.md §37)** are explicit repository lookup
  methods, not inferred: `AssetRepository.FindByHostname`,
  `SoftwareRepository.FindByNaturalKey` (asset+vendor+product+version),
  `FindingRepository.FindByAssetAndVulnerability`. `DiscoverAssets`,
  `InventoryAsset`, and `CorrelateFindings` all follow the same
  find-then-`Observe`/`Confirm`-or-`New` shape.
- **Two APIs beyond §26's list were added** because the domain is unusable
  without them: `ApproveRemediationPlan` (remediation.Plan's own state
  machine, ADR 0003, refuses Proposed -> InProgress directly) and the
  five Exception operations (`RequestException`, `ApproveException`,
  `RejectException`, `ExpireException`, `RevokeException` — AGENTS.md §18,
  Phase 4, has no Named API examples of its own). §26 introduces its list
  with "例" (examples), so this is filling a gap, not overriding the
  spec. `PreviewRemediation` was also added to expose `Plan.DryRun`
  (§33) at the Application layer.
- **Audit entries are recorded only for the actions §30 actually names**:
  `risk_change`, `priority_change`, `remediation_approval`,
  `remediation_execution`, `verification`, `exception_creation`,
  `exception_approval`, `exception_expiration`. Unlike some other lists in
  AGENTS.md, §30's is not qualified with "など"/"例", so it is treated as
  the definitive set. `CreateRemediationPlan`, `RecordEvidence`,
  `RejectException`, and `RevokeException` do not produce audit entries as
  a result — each is called out in its own doc comment. If broader
  auditing (e.g. of rejections/revocations) turns out to be needed, that
  is a deliberate scope decision for a future ADR, not an oversight to
  silently patch in.
- `AssessRisk` and `CalculatePriority` record their audit entries with
  `Who: "system"`, since they are deterministic, automated computations
  (AGENTS.md §8, §12) with no human actor to name; their `Why` cites the
  Policy name/version that produced the result, and `Before`/`After` are
  JSON snapshots built by `toJSON` in `snapshot.go` — Domain does not
  serialize itself (AGENTS.md §25).
- `CalculatePriority` requires a `risk.Assessment` to already exist for
  the Finding (`assess_risk` must run first), matching the Risk ->
  Priority pipeline order in AGENTS.md §24.

## Consequences

- Infrastructure's job (a future phase) is to implement each repository
  port against PostgreSQL and `RemediationExecutor` against the actual
  command-execution pipeline — none of `Service`'s logic should need to
  change when that happens.
- Anything that calls `Service` (CLI, API) can be tested against the
  in-memory fakes already written for this package's own tests
  (`fakes_test.go`) without a real database.
- Because ports return `(nil, nil)` for "not found", every Named API
  method must check for a nil result itself; a future real
  implementation must preserve that contract rather than returning a
  wrapped "not found" error.
