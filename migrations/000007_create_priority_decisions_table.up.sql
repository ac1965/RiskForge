CREATE TABLE priority_decisions (
    id                   UUID PRIMARY KEY,
    finding_id           UUID NOT NULL REFERENCES findings (id),
    risk_assessment_id   UUID NOT NULL REFERENCES risk_assessments (id),
    rank                 DOUBLE PRECISION NOT NULL,
    level                TEXT NOT NULL CHECK (level IN ('critical', 'high', 'medium', 'low')),
    factors              JSONB NOT NULL,
    sla_deadline         TIMESTAMPTZ NOT NULL,
    policy_name          TEXT NOT NULL,
    policy_version       TEXT NOT NULL DEFAULT '',
    decided_at           TIMESTAMPTZ NOT NULL
);

CREATE INDEX priority_decisions_finding_id_decided_at_idx
    ON priority_decisions (finding_id, decided_at DESC);
