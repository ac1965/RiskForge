-- Verification is kept separate from remediation_plans (AGENTS.md §44
-- Invariant 3): completing a plan means a change was made, not that it
-- was confirmed effective.
CREATE TABLE verifications (
    id            UUID PRIMARY KEY,
    finding_id    UUID NOT NULL REFERENCES findings (id),
    method        TEXT NOT NULL CHECK (method IN (
        'version_check', 'configuration_check', 'package_check',
        'scanner_rescan', 'service_check'
    )),
    verified_at   TIMESTAMPTZ NOT NULL,
    result        TEXT NOT NULL CHECK (result IN ('pass', 'fail', 'inconclusive')),
    -- A verification result must always be backed by evidence of how it
    -- was obtained (AGENTS.md §16, §20A.6).
    evidence_id   UUID NOT NULL REFERENCES evidence (id)
);

CREATE INDEX verifications_finding_id_idx ON verifications (finding_id);
