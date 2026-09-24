# 0009. PostgreSQL persistence and migrations

## Status

Accepted

## Context

AGENTS.md §29 lists the tables the schema must keep separate and §25A.1
names PostgreSQL + golang-migrate as the stack. Implementing this against
the ports defined in `internal/application/ports.go` (ADR 0008) required
resolving a few things §29 doesn't spell out directly.

## Decision

- **Driver**: `database/sql` with `github.com/jackc/pgx/v5/stdlib` as the
  driver, not pgx's native (non-`database/sql`) interface. This keeps
  every repository written against the standard library interface and
  lets `golang-migrate`'s `database/postgres` driver (which wraps `*sql.DB`)
  work unmodified.
- **Arrays and structured data go in `JSONB`, not native Postgres arrays
  or enum types.** `Asset.IPAddresses`/`MACAddresses`,
  `Vulnerability.CWE`/`AffectedProducts`, and `risk.Assessment.Factors`/
  `priority.Decision.Factors` are all stored as JSONB and
  marshaled/unmarshaled with `encoding/json` in Go. This sidesteps
  `database/sql`-via-pgx's more involved native array scanning and keeps
  every column readable with a plain `Scan` call. Enums (`asset_type`,
  `severity`, `status`, ...) are `TEXT` with a `CHECK` constraint, not a
  Postgres `ENUM` type, since altering the allowed set of a Postgres enum
  (`ALTER TYPE ... ADD VALUE`) is more disruptive than updating a `CHECK`
  constraint in a later migration. Open-ended fields (`evidence.type`,
  `audit_log.action`, `findings.detection_source`) have no `CHECK` at all,
  matching their Go types being plain strings rather than closed enums.
- **The `findings.evidence_id` ↔ `evidence.finding_id` circular reference**
  is resolved by creating `findings` first (migration `000004`) with an
  unconstrained `evidence_id UUID` column, then adding the actual foreign
  key in migration `000005` once `evidence` exists. The down migration for
  `000005` drops that constraint before dropping the table.
- **§29 lists `remediation_actions` separately from `remediation_plans`**,
  but the domain model (Phase 3, ADR 0003) only has one entity —
  `remediation.Plan` — matching §14's exact field list, which already
  includes `action_type`, `status`, `executed_at`. Introducing a second
  domain entity now, purely to satisfy a table name mentioned once in
  §29's diagram, would be schema design speculative of a requirement that
  was never concretely specified (§14 never gives a separate
  RemediationAction field list the way it does for RemediationPlan). One
  table, `remediation_plans`, is used; if per-attempt execution history
  (e.g. multiple retries of one plan) becomes a real requirement, that is
  a new domain concept deserving its own ADR, not something to guess at
  here.
- **`audit_log` is added even though it is not in §29's list**, since
  persisting `audit.Entry` (§30, Phase 4) requires a table and no other
  name in §29 fits. `subject_id` is `TEXT`, not a foreign key, matching
  `audit.Entry.SubjectType`/`SubjectID` being a generic, un-typed
  reference by design (ADR 0007).
- **Append-only vs. upsert**: `assets`, `software_installations`,
  `vulnerabilities`, `findings`, `remediation_plans`, and `exceptions` use
  `INSERT ... ON CONFLICT (id) DO UPDATE` because their domain types are
  mutable aggregates the Application layer re-saves after a state change
  (`Observe`, `TransitionTo`, `Approve`, ...). `risk_assessments`,
  `priority_decisions`, and `verifications` are plain `INSERT` with no
  `ON CONFLICT` clause: each `risk.Engine.Assess` / `priority.Engine.Decide`
  / recorded `Verification` call is meant to produce a new historical row,
  found later via `FindLatestByFinding`'s `ORDER BY ... DESC LIMIT 1`, not
  overwrite the previous one. `evidence` and `audit_log` use
  `INSERT ... ON CONFLICT (id) DO NOTHING` (evidence) or plain `INSERT`
  (audit_log): both are immutable by domain design (no update method
  exists on `evidence.Evidence` or `audit.Entry`), so
  `internal/infrastructure/postgres` never issues an `UPDATE` against
  either table.
- **Migrations are embedded via `go:embed`** (`migrations/embed.go`) so
  `postgres.Migrate(db)` can apply them without requiring the `migrate`
  CLI to be installed, while `/migrations/*.sql` stays the single source
  of truth usable by the CLI form too (`make migrate-up`).
- **Integration tests are gated behind a `//go:build integration` tag**
  (`internal/infrastructure/postgres/integration_test.go`) and start a
  real PostgreSQL container per test via testcontainers-go (AGENTS.md
  §25A.6), rather than mocking `database/sql`. `go test ./...` (no tags)
  never touches Docker; `make test-integration` (`go test -tags=integration
  ./...`) does, and CI runs both as separate jobs. Because these
  integration-only imports live behind a build tag, plain `go mod tidy`
  can't see them and will drop them from `go.mod`/`go.sum` — `make tidy`
  runs `GOFLAGS=-tags=integration go mod tidy` instead.

## Consequences

- Every repository is exercised against real PostgreSQL by
  `integration_test.go`, not just compiled against the port interfaces
  (ADR 0008 already has compile-time `var _ application.XRepository =
  (*XRepository)(nil)` assertions in `interfaces.go`); a schema/query
  mismatch is caught by `make test-integration`, not left for
  production.
- `EvidenceRepository.Save` and `AuditRepository.Save` being the only
  write paths to their tables, with no corresponding `Update`, is the
  concrete DB-level enforcement of "Evidence/Audit are never modified
  after creation" — the same invariant the domain types already encode by
  having no setters.
- Adding a genuinely new `remediation_actions` concept later requires a
  new migration, a new domain type, and updating ADR 0003 or superseding
  it — not silently repurposing the existing `remediation_plans` table.
