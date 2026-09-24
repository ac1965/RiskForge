# Migrations

Schema migrations are managed with [golang-migrate](https://github.com/golang-migrate/migrate)
(AGENTS.md §25A.1, §29). The database schema is designed from the domain
model, not the other way around: `assets`, `software_installations`,
`vulnerabilities`, `findings`, `risk_assessments`, `priority_decisions`,
`remediation_plans`, `remediation_actions`, `verifications`, `evidence`, and
`exceptions` are kept as separate tables (AGENTS.md §29) — no single
catch-all `vulnerabilities` table.

Create a new migration pair:

```bash
migrate create -ext sql -dir migrations -seq <name>
```

Apply migrations:

```bash
migrate -database "$RISKFORGE_DATABASE_URL" -path migrations up
```

No migrations exist yet — Phase 1 (AGENTS.md §45) introduces the first ones
for `assets`, `software_installations`, `vulnerabilities`, and `findings`.
