# 0010. CLI wiring

## Status

Accepted

## Context

`internal/cli` (from the initial scaffolding) already had the command
tree AGENTS.md §27 shows, but every `RunE` returned "not implemented
yet". Wiring it to real persistence raised the same kind of question ADRs
0008 and 0009 already answered for Application and Infrastructure: §27's
list is a starting structure ("CLIは以下のような構造を基本とする"), not
necessarily exhaustive, and several of its commands have no way to
produce data for `list`/`show` to display, or no way to reach the
approval/execution/exception operations built in earlier phases.

## Decision

- **Composition root**: `cmd/riskforge/main.go`, not `internal/cli`,
  imports `internal/infrastructure/postgres` and constructs the
  `risk.Engine`/`priority.Engine`. It passes `internal/cli.NewRootCommand`
  a `ServiceFactory` (`func() (*application.Service, func() error,
  error)`) and a `migrate func() error`. `internal/cli` itself only
  imports `internal/application` and `internal/domain` value types (for
  building `Params` structs and reading enum constants from flags) —
  never `internal/infrastructure` — keeping the layering rule (AGENTS.md
  §25) intact even though the binary as a whole obviously needs
  PostgreSQL.
- **The factory is lazy**: each command calls `newService()` inside its
  own `RunE`, not at `NewRootCommand` construction time. This is why
  `riskforge --help` and `riskforge --version` work without
  `$RISKFORGE_DATABASE_URL` being set at all, while every real command
  fails immediately and clearly if it isn't.
- **Application ports gained `List`/`ListLatest` methods**
  (`AssetRepository.List`, `FindingRepository.List`,
  `RemediationPlanRepository.List`, `ExceptionRepository.List`,
  `PriorityDecisionRepository.ListLatest`) that didn't exist before this
  phase — nothing needed them until the CLI's `list` commands did. Each
  is implemented in `internal/infrastructure/postgres` and covered by
  its own integration test; `PriorityDecisionRepository.ListLatest` uses
  `SELECT DISTINCT ON (finding_id) ... ORDER BY finding_id, decided_at
  DESC` to get the newest decision per Finding, verified against a
  fixture with two decisions for the same Finding at different ranks.
- **Commands beyond §27's literal list** were added because the ones
  already there don't compose into a usable system on their own:
  - `asset discover`, `vulnerability add`, `finding correlate`: nothing
    else can create an Asset, Vulnerability, or Finding via the CLI.
    `vulnerability add` is explicitly a manual stand-in — real ingestion
    is the NVD/KEV/OSV Data Source Adapters (§19), which are Phase 5.
  - `remediation approve`, `remediation preview`, `remediation execute`:
    `remediation propose` alone can never move past `StatusProposed`
    (ADR 0003's approval gate).
  - `exception request`/`approve`/`reject`/`expire`/`revoke`: §27 shows
    only `exception list`; Exception (§18, Phase 4) otherwise has no CLI
    entry point at all.
  - `priority calculate`: paired with `risk assess` as the write half of
    the Risk → Priority pipeline, so `priority list` can stay a pure
    read instead of quietly computing decisions as a side effect of
    listing them.
  - `evidence record`: `verify` and `exception request` both need an
    Evidence id to reference.
  - `migrate`: makes the `riskforge` binary self-sufficient for schema
    setup, reusing `postgres.Migrate` (ADR 0009) instead of requiring the
    external `migrate` CLI.
- **`remediation execute` uses a placeholder `manualExecutor`**
  (`internal/cli/remediation.go`) that always reports success. The
  validated/structured/allowlisted command execution AGENTS.md §31/§32
  actually require doesn't exist yet (see ADR 0008's `RemediationExecutor`
  port); this assumes the operator already made the change by hand and
  the CLI is just recording that fact, which is honest about what a v1
  CLI without real execution infrastructure can promise.
- **Batch commands (`risk assess`, `priority calculate`) continue past a
  single item's failure**, printing `finding <id>: error: ...` per
  failure and returning a non-zero exit only after processing every
  target — so one bad Finding doesn't block assessing the rest.
- **`RISKFORGE_DATABASE_URL`** is the one piece of configuration the CLI
  reads (matching the Makefile's `migrate-up`/`migrate-down` targets,
  which already used this name).

## Consequences

- `cmd/riskforge/main.go` is the only place that would need to change to
  point the CLI at a different Provider set (e.g. a real CMDB-backed
  `BusinessImpactProvider` once one exists) or a different persistence
  backend — `internal/cli` itself has no idea PostgreSQL exists.
- Verified end-to-end against a real PostgreSQL instance (`docker compose
  up` + the built binary), not just unit-level: asset discover → asset
  list/inspect → vulnerability add → finding correlate → finding
  list/show → risk assess → priority calculate/list → remediation
  propose → (execute correctly refused before approve) → approve →
  preview → execute → finding reaches `remediated` → evidence record →
  verify → finding reaches `verified`; separately, exception request
  (rejected once for exceeding an org duration cap, accepted once within
  it) → approve → finding reaches `accepted` → expire → finding reaches
  `reopened`.
- `root.SilenceErrors` is `true` because `cmd/riskforge/main.go` already
  prints whatever error `Execute()` returns; leaving cobra's own default
  `false` printed every command error twice, which the end-to-end pass
  above caught immediately.
