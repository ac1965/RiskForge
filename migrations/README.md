# Migrations

Schema migrations are managed with [golang-migrate](https://github.com/golang-migrate/migrate)
(AGENTS.md §25A.1, §29). The database schema is designed from the domain
model, not the other way around: `assets`, `software_installations`,
`vulnerabilities`, `findings`, `evidence`, `risk_assessments`,
`priority_decisions`, `remediation_plans`, `verifications`, and
`exceptions` are kept as separate tables — no single catch-all
`vulnerabilities` table. `audit_log` is also a separate table; it is not
in AGENTS.md §29's explicit list but is needed to persist `audit.Entry`
(§30, Phase 4).

`§29` also lists a `remediation_actions` table distinct from
`remediation_plans`. The domain model (`internal/domain/remediation`)
only has one entity, `Plan`, matching §14's field list — `remediation_actions`
is treated as the same concept and is not a separate table (see
[docs/adr/0009-postgres-persistence.md](../docs/adr/0009-postgres-persistence.md)).

`findings.evidence_id` and `evidence.finding_id` reference each other;
the circular dependency is resolved by creating `findings` first with a
plain (unconstrained) `evidence_id` column, then adding the foreign key
once `evidence` exists (migration `000005`).

`embed.go` in this directory embeds these `.sql` files via `go:embed` so
`internal/infrastructure/postgres.Migrate` can apply them without
requiring the `migrate` CLI to be installed — this directory is the
single source of truth either way.

Create a new migration pair:

```bash
migrate create -ext sql -dir migrations -seq <name>
```

Apply migrations with the CLI:

```bash
migrate -database "$RISKFORGE_DATABASE_URL" -path migrations up
```

or programmatically:

```go
db, err := postgres.Open(dsn)
// ...
err = postgres.Migrate(db)
```

`make migrate-up` / `make migrate-down` wrap the CLI form using
`$RISKFORGE_DATABASE_URL`.
