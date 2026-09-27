-- Principals are "who" a bearer token belongs to (ADR 0012): a human
-- operator or a service/automation account. They carry no credentials
-- themselves; api_tokens (migration 000013) does.
CREATE TABLE principals (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL CHECK (kind IN ('human', 'service')),
    created_at  TIMESTAMPTZ NOT NULL
);
