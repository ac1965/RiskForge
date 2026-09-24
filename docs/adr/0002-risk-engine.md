# 0002. Risk and Priority Engine design

## Status

Accepted

## Context

AGENTS.md §8 and §12 require Risk and Priority to be computed by
independent, composable engines rather than a fixed formula (e.g. a
mechanical CVSS-weighted multiplication), and forbid treating Risk and
Priority as the same thing (§44 Invariants 2 and 5). At the same time,
§23 describes a full, configuration-driven Policy Engine — but that is
explicitly Phase 4 work (§45), not Phase 2. Phase 2 needs a design that:

- lets Risk and Priority scoring be swapped out later without changing
  callers, and
- doesn't build the Phase 4 Policy Engine (config loading, persistence,
  approval workflow) ahead of schedule (§47.11).

## Decision

Implement `internal/domain/risk` and `internal/domain/priority` as a pair
of parallel Engine/Policy/Provider structures:

- **Providers** (`SeverityProvider`, `ExploitabilityProvider`,
  `AssetCriticalityProvider`, `ExposureProvider`, `BusinessImpactProvider`
  for Risk; `RemediationAvailabilityProvider`, `BusinessConstraintsProvider`
  for Priority, plus reuse of Risk's Exploitability/AssetCriticality/
  Exposure providers) are interfaces gathering one input each. Concrete
  implementations that call out to a CMDB, KEV feed, or EPSS API are an
  infrastructure concern for a later phase; for now, default
  implementations (`FromVulnerabilityProvider`, `FromAssetProvider`, ...)
  simply read from the already-loaded Asset/Vulnerability/Finding
  aggregates.
- **Policy** (`risk.Policy`, `priority.Policy`) is the single seam where
  scoring logic lives: `Evaluate(...)` takes the gathered provider outputs
  and returns a `Result` (score/rank, level, and `explainability.Factor`s).
  `Engine.Assess` / `Engine.Decide` never compute a score themselves — they
  only gather inputs and call Policy.
- `risk.BaselinePolicy` and `priority.BaselinePolicy` are one reference
  implementation of Policy each, not "the" risk/priority formula. They
  exist so the Engines are usable and testable now; a config-driven Policy
  Engine (§23) can later be introduced as another `Policy` implementation
  without touching `Engine`.
- `risk.Assessment` and `priority.Decision` are separate entities.
  `priority.Engine` takes a `*risk.Assessment` as one of several Policy
  inputs but computes its own independent Rank/Level — it is not a
  read-through of Risk's Level (§44 Invariant 2).
- Every `Policy.Evaluate` result must include at least one
  `explainability.Factor` (§40); `risk.New` / `priority.New` reject an
  Assessment/Decision with zero factors, so an unexplained score cannot be
  persisted.
- `risk.Exploitability` is a value object separate from
  `vulnerability.Vulnerability`'s own exploit fields: it represents
  time-varying threat intel (KEV listing, exploit prediction) gathered
  fresh per assessment, not the vulnerability's static description (§9).

## Consequences

- Adding a real Policy (e.g. loaded from YAML/DB config in Phase 4) means
  writing a new type that implements `Policy`, not modifying `Engine`.
- Swapping in a live KEV/EPSS-backed `ExploitabilityProvider` or a
  CMDB-backed `BusinessImpactProvider` later is an infrastructure change,
  isolated from the Risk/Priority domain logic.
- `risk.BaselinePolicy` and `priority.BaselinePolicy`'s specific weights
  are illustrative defaults, not organizational policy; they should not be
  relied on for production risk decisions without review.
