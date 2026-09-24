-- A Finding is the fact that a Vulnerability was detected on an Asset; it
-- is never the same thing as the Vulnerability itself (AGENTS.md §44
-- Invariant 1).
CREATE TABLE findings (
    id                  UUID PRIMARY KEY,
    asset_id            UUID NOT NULL REFERENCES assets (id),
    vulnerability_id    UUID NOT NULL REFERENCES vulnerabilities (id),
    detection_source    TEXT NOT NULL,
    detected_at         TIMESTAMPTZ NOT NULL,
    last_confirmed_at   TIMESTAMPTZ NOT NULL,
    status              TEXT NOT NULL CHECK (status IN (
        'open', 'mitigated', 'remediated', 'verified', 'reopened',
        'accepted', 'false_positive'
    )),
    confidence          TEXT NOT NULL CHECK (confidence IN (
        'confirmed', 'high', 'medium', 'low', 'unknown'
    )),
    -- evidence_id references evidence(id), added once that table exists
    -- (migration 000005) to avoid a circular table dependency.
    evidence_id         UUID,
    -- CorrelateFindings's idempotency key (AGENTS.md §37).
    CONSTRAINT findings_asset_vulnerability_key UNIQUE (asset_id, vulnerability_id)
);

CREATE INDEX findings_asset_id_idx ON findings (asset_id);
CREATE INDEX findings_vulnerability_id_idx ON findings (vulnerability_id);
CREATE INDEX findings_status_idx ON findings (status);
