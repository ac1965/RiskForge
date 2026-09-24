# 0001. Core domain model and layering

## Status

Accepted

## Context

RiskForge must manage Asset → Software → Vulnerability → Finding → Risk →
Priority → Remediation → Verification → Evidence as a lifecycle, not as a
CVSS-sorted list (AGENTS.md §1–§2). This requires the domain entities and
invariants to be fixed before any implementation begins, so that later
phases don't quietly collapse distinct concepts (e.g. Vulnerability and
Finding) for convenience.

## Decision

Adopt the domain model, invariants, and layering defined in AGENTS.md
§3–§25 as-is:

- Entities: `Organization`, `Asset`, `SoftwareInstallation`,
  `Vulnerability`, `Finding`, `RiskAssessment`, `PriorityDecision`,
  `RemediationPlan`, `Verification`, `Evidence`, `Exception`.
- Invariants (§44): Vulnerability ≠ Finding, Risk ≠ Priority,
  Remediation ≠ Verification, Finding ≠ Evidence, CVSS ≠ Organizational
  Risk, Detected ≠ Verified Remediated.
- Layering: UI → Application → Domain → Infrastructure (§25). Domain code
  never imports HTTP clients, database drivers, CLI packages, OS command
  execution, or cloud SDKs directly.
- Repository layout: `internal/domain/<entity>`, `internal/application`,
  `internal/infrastructure/<adapter>`, `internal/api`, `internal/cli`,
  mirroring this layering directly in the package graph.

## Consequences

- Adding a feature that would blur an invariant (e.g. writing Risk directly
  into a Finding record) requires a new ADR, not a quiet code change
  (AGENTS.md §47.12).
- Domain packages stay free of external dependencies, which keeps unit
  testing the Risk Engine and Priority Engine (AGENTS.md §25A.6) cheap.
- Phase 1 (AGENTS.md §45) implements only `Asset`, `Software`,
  `Vulnerability`, and `Finding`; the remaining entities are scaffolded as
  empty packages/tables in later phases, not built ahead of schedule
  (AGENTS.md §47.11).
