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

Phase 1 (AGENTS.md §45) is in progress: the Asset, Software, Vulnerability,
and Finding domain models are implemented under `internal/domain/`, with
unit tests covering validation and the Finding status lifecycle. The
application layer, PostgreSQL persistence, migrations, and CLI wiring
(currently stubs per AGENTS.md §27) are not yet implemented. See
[docs/adr/](docs/adr/) for recorded design decisions.
