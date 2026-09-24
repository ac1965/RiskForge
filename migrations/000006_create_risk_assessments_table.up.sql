-- risk_assessments is kept separate from findings and priority_decisions
-- (AGENTS.md §29, §44 Invariants 2 and 5: Risk != Priority, CVSS !=
-- Organizational Risk).
CREATE TABLE risk_assessments (
    id              UUID PRIMARY KEY,
    finding_id      UUID NOT NULL REFERENCES findings (id),
    score           DOUBLE PRECISION NOT NULL,
    level           TEXT NOT NULL CHECK (level IN (
        'critical', 'high', 'medium', 'low', 'unknown'
    )),
    -- factors is a JSON array of {name, value, reason}, required by
    -- risk.New to be non-empty (AGENTS.md §40: a score must always be
    -- explainable).
    factors         JSONB NOT NULL,
    policy_name     TEXT NOT NULL,
    policy_version  TEXT NOT NULL DEFAULT '',
    assessed_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX risk_assessments_finding_id_assessed_at_idx
    ON risk_assessments (finding_id, assessed_at DESC);
