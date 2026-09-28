-- Persists a RawFinding once the Matcher (ADR 0015/0016/0017) classifies
-- it as "unclassified" (AGENTS.md §20A.2 case 3, "分類できない場合は、
-- Confidenceを下げたRawFindingとして保留する") -- held for later review,
-- not discarded and not acted on automatically (ADR 0018).
CREATE TABLE raw_findings (
    id                    UUID PRIMARY KEY,
    source                TEXT NOT NULL,
    source_ref            TEXT NOT NULL DEFAULT '',
    asset_id              UUID NOT NULL REFERENCES assets (id),
    -- evidence_id is optional: not every RawFinding is backed by a
    -- separately-stored Evidence record (see rawfinding.RawFinding).
    evidence_id           UUID REFERENCES evidence (id),
    title                 TEXT NOT NULL,
    detail                TEXT NOT NULL DEFAULT '',
    confidence            TEXT NOT NULL,
    cvss_v3               DOUBLE PRECISION,
    cvss_vector           TEXT NOT NULL DEFAULT '',
    native_severity       TEXT NOT NULL DEFAULT '',
    attack_technique_ids  JSONB NOT NULL DEFAULT '[]',
    collected_at          TIMESTAMPTZ NOT NULL
);

CREATE INDEX raw_findings_asset_id_idx ON raw_findings (asset_id);
