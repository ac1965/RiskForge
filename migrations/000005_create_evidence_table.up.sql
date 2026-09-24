-- Evidence is first-class and immutable (AGENTS.md §17, §22, §47.10):
-- there is deliberately no UPDATE path for this table in
-- internal/infrastructure/postgres, only INSERT and SELECT.
CREATE TABLE evidence (
    id            UUID PRIMARY KEY,
    type          TEXT NOT NULL,
    source        TEXT NOT NULL,
    collected_at  TIMESTAMPTZ NOT NULL,
    asset_id      UUID NOT NULL REFERENCES assets (id),
    -- finding_id is optional: evidence may be collected before it is
    -- correlated to a specific Finding (AGENTS.md §17).
    finding_id    UUID REFERENCES findings (id),
    content_hash  TEXT NOT NULL,
    location      TEXT NOT NULL
);

CREATE INDEX evidence_asset_id_idx ON evidence (asset_id);
CREATE INDEX evidence_finding_id_idx ON evidence (finding_id);

ALTER TABLE findings
    ADD CONSTRAINT findings_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES evidence (id);
