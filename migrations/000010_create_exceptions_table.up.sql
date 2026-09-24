-- Exceptions are never permanent by default (AGENTS.md §18):
-- expires_at is always required.
CREATE TABLE exceptions (
    id                    UUID PRIMARY KEY,
    finding_id            UUID NOT NULL REFERENCES findings (id),
    reason                TEXT NOT NULL,
    requested_by          TEXT NOT NULL,
    approved_by           TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    compensating_control  TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL CHECK (status IN (
        'requested', 'approved', 'rejected', 'expired', 'revoked'
    ))
);

CREATE INDEX exceptions_finding_id_idx ON exceptions (finding_id);
CREATE INDEX exceptions_status_expires_at_idx ON exceptions (status, expires_at);
