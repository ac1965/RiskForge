# RiskForge

Vulnerability & Exposure Management Platform.

Manages the full lifecycle — Asset → Software → Vulnerability → Risk →
Prioritization → Remediation → Verification → Evidence — rather than acting
as a plain vulnerability scanner. See [AGENTS.md](AGENTS.md) for the full
domain model, architecture, and development constraints; this README only
covers day-to-day commands.

## Stack

Go 1.24+, PostgreSQL, golang-migrate, Cobra CLI, `net/http`. See
[AGENTS.md §25A](AGENTS.md#25a-technology-stack).

## Binaries

- `riskforge` — CLI / API server
- `riskforge-agent` — runs on managed assets (Scanner privileges)
- `riskforge-worker` — background jobs (Remediation execution privileges)

Binaries are kept separate to physically enforce the permission separation
described in AGENTS.md §31 and §25A.3.

## Development

```bash
make up      # start PostgreSQL via Docker Compose
make build   # build all three binaries into ./bin
make test    # go test ./...
make vet     # go vet ./...
```

Database schema migrations live under [migrations/](migrations/) and are
managed with golang-migrate — see [migrations/README.md](migrations/README.md).

## Status

Phase 1 (AGENTS.md §45) domain models — Asset, Software, Vulnerability,
Finding — are implemented under `internal/domain/`, with unit tests
covering validation and the Finding status lifecycle.

Phase 2 domain models — Risk and Priority — are also implemented:
`internal/domain/risk` (the Risk Engine, §8) and `internal/domain/priority`
(the Priority Engine, §12) each compose pluggable providers and a Policy,
producing an explainable Assessment/Decision (§40) without hardcoding the
scoring formula. The Dashboard part of Phase 2 (§41, frontend) is not
started (§25A.7: frontend work begins after backend/CLI/API).

Phase 3 domain models — Remediation, Verification, Evidence — are also
implemented: `internal/domain/remediation` (RemediationPlan, §13–§14),
`internal/domain/verification` (§16), and `internal/domain/evidence`
(§17). Automatic-remediation policy configuration (§15's
`auto_remediation_policy`) was deferred to Phase 4.

Phase 4 domain models — Exception, Policy, Audit — are also implemented:
`internal/domain/exception` (§18, with an `exception.Policy` capping how
long an exception may run), `internal/domain/policy`
(`AutoRemediationPolicy` from §15, denying automatic execution by
default), and `internal/domain/audit` (§30, an immutable who/what/when/why
/before/after record). A generic, persisted, versioned Policy-document
aggregate was deliberately not built — see
[docs/adr/0007-exception-policy-audit.md](docs/adr/0007-exception-policy-audit.md)
for why.

The Application layer's Named APIs (AGENTS.md §26) are also implemented in
`internal/application`: `DiscoverAssets`, `InventoryAsset`,
`CorrelateFindings`, `AssessRisk`, `CalculatePriority`,
`CreateRemediationPlan`/`ApproveRemediationPlan`/`PreviewRemediation`/
`ExecuteRemediation`, `VerifyRemediation`, `RecordEvidence`, and the
Exception workflow (`RequestException`, `ApproveException`,
`RejectException`, `ExpireException`, `RevokeException`). These depend
only on repository port interfaces (`ports.go`) and the Phase 2 engines —
no database yet. See
[docs/adr/0008-application-layer.md](docs/adr/0008-application-layer.md)
for the ports design and which operations are audited.

PostgreSQL persistence, migrations, and CLI wiring (currently stubs per
AGENTS.md §27) are not yet implemented. See [docs/adr/](docs/adr/) for
recorded design decisions.
