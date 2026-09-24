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

Phase 1 (AGENTS.md §45) is in progress: Asset, Software, Vulnerability, and
Finding domain packages exist as skeletons under `internal/domain/` awaiting
implementation. The CLI (`internal/cli/`) is wired per AGENTS.md §27 with
stub commands. See [docs/adr/](docs/adr/) for recorded design decisions.
