-- Only the SHA-256 hash of a bearer token is ever stored (ADR 0012,
-- AGENTS.md §31): the raw token exists only once, at issuance, in the
-- CLI operator's terminal. expires_at/revoked_at/last_used_at are
-- nullable — a token issued without an expiry never expires on its own.
CREATE TABLE api_tokens (
    id            UUID PRIMARY KEY,
    principal_id  UUID NOT NULL REFERENCES principals (id),
    token_hash    TEXT NOT NULL UNIQUE,
    scopes        JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX api_tokens_principal_id_idx ON api_tokens (principal_id);
