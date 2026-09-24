CREATE TABLE vulnerabilities (
    id                          UUID PRIMARY KEY,
    -- cve_id is empty for vulnerabilities with no CVE (AGENTS.md §20A.2).
    cve_id                      TEXT NOT NULL DEFAULT '',
    title                       TEXT NOT NULL,
    description                 TEXT NOT NULL DEFAULT '',
    severity                    TEXT NOT NULL CHECK (severity IN (
        'critical', 'high', 'medium', 'low', 'none', 'unknown'
    )),
    cvss_v3                     DOUBLE PRECISION,
    cvss_v4                     DOUBLE PRECISION,
    cwe                         JSONB NOT NULL DEFAULT '[]',
    affected_products           JSONB NOT NULL DEFAULT '[]',
    published_at                TIMESTAMPTZ,
    modified_at                 TIMESTAMPTZ,
    -- exploit_available (exploit_exists) and exploitation_observed are
    -- kept as independent booleans on purpose (AGENTS.md §9).
    exploit_available           BOOLEAN NOT NULL DEFAULT FALSE,
    exploitation_observed       BOOLEAN NOT NULL DEFAULT FALSE,
    remediation_available       BOOLEAN NOT NULL DEFAULT FALSE,
    -- Provenance of externally sourced data (AGENTS.md §6, §38); left
    -- empty for vulnerabilities defined entirely in-house.
    provenance_source           TEXT NOT NULL DEFAULT '',
    provenance_source_id        TEXT NOT NULL DEFAULT '',
    provenance_source_version   TEXT NOT NULL DEFAULT '',
    provenance_retrieved_at     TIMESTAMPTZ,
    provenance_raw_reference    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX vulnerabilities_cve_id_idx ON vulnerabilities (cve_id) WHERE cve_id <> '';
