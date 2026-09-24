-- audit_log is not in AGENTS.md §29's explicit table list, but is needed
-- to persist audit.Entry (AGENTS.md §30, Phase 4). subject_id is TEXT,
-- not a foreign key, since it generically references whatever kind of
-- record subject_type names (finding, remediation_plan, ...) without this
-- table depending on every other one.
--
-- There is deliberately no UPDATE or DELETE path for this table in
-- internal/infrastructure/postgres: an audit trail that could be edited
-- after the fact would defeat its purpose (AGENTS.md §30).
CREATE TABLE audit_log (
    id            UUID PRIMARY KEY,
    action        TEXT NOT NULL,
    who           TEXT NOT NULL,
    subject_type  TEXT NOT NULL,
    subject_id    TEXT NOT NULL,
    what          TEXT NOT NULL,
    why           TEXT NOT NULL,
    before        TEXT NOT NULL DEFAULT '',
    after         TEXT NOT NULL DEFAULT '',
    occurred_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX audit_log_subject_idx ON audit_log (subject_type, subject_id);
CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at);
