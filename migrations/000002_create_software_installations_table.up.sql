CREATE TABLE software_installations (
    id                UUID PRIMARY KEY,
    asset_id          UUID NOT NULL REFERENCES assets (id),
    vendor            TEXT NOT NULL,
    product           TEXT NOT NULL,
    version           TEXT NOT NULL,
    architecture      TEXT NOT NULL DEFAULT '',
    package_manager   TEXT NOT NULL DEFAULT '',
    install_path      TEXT NOT NULL DEFAULT '',
    -- cpe/purl are best-effort standard identifiers (AGENTS.md §5); left
    -- empty when not available. Version alone must not drive matching.
    cpe               TEXT NOT NULL DEFAULT '',
    purl              TEXT NOT NULL DEFAULT '',
    first_seen        TIMESTAMPTZ NOT NULL,
    last_seen         TIMESTAMPTZ NOT NULL,
    -- InventoryAsset's idempotency key (AGENTS.md §37).
    CONSTRAINT software_installations_natural_key UNIQUE (asset_id, vendor, product, version)
);

CREATE INDEX software_installations_asset_id_idx ON software_installations (asset_id);
