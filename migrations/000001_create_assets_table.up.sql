CREATE TABLE assets (
    id                                          UUID PRIMARY KEY,
    hostname                                    TEXT NOT NULL,
    fqdn                                        TEXT NOT NULL DEFAULT '',
    ip_addresses                                JSONB NOT NULL DEFAULT '[]',
    mac_addresses                               JSONB NOT NULL DEFAULT '[]',
    asset_type                                  TEXT NOT NULL CHECK (asset_type IN (
        'server', 'workstation', 'laptop', 'container', 'virtual_machine',
        'cloud_instance', 'network_device', 'database', 'application',
        'mobile_device', 'iot', 'unknown'
    )),
    operating_system                            TEXT NOT NULL DEFAULT '',
    environment                                 TEXT NOT NULL CHECK (environment IN (
        'production', 'staging', 'development', 'test', 'management', 'unknown'
    )),
    owner                                        TEXT NOT NULL DEFAULT '',
    business_unit                                TEXT NOT NULL DEFAULT '',
    -- criticality reflects business context (AGENTS.md §11), never CVSS
    -- (§44 Invariant 5).
    criticality                                  TEXT NOT NULL CHECK (criticality IN (
        'critical', 'high', 'medium', 'low', 'unknown'
    )),
    exposure_internet_exposed                    BOOLEAN NOT NULL DEFAULT FALSE,
    exposure_externally_accessible               BOOLEAN NOT NULL DEFAULT FALSE,
    exposure_public_ip                           BOOLEAN NOT NULL DEFAULT FALSE,
    exposure_reachable_from_untrusted_network    BOOLEAN NOT NULL DEFAULT FALSE,
    exposure_remote_access_enabled               BOOLEAN NOT NULL DEFAULT FALSE,
    exposure_service_exposed                     BOOLEAN NOT NULL DEFAULT FALSE,
    exposure_level                               TEXT NOT NULL CHECK (exposure_level IN (
        'direct', 'indirect', 'internal_only', 'restricted', 'unknown'
    )),
    first_seen                                   TIMESTAMPTZ NOT NULL,
    last_seen                                    TIMESTAMPTZ NOT NULL,
    lifecycle_state                              TEXT NOT NULL CHECK (lifecycle_state IN (
        'active', 'inactive', 'decommissioned', 'unknown'
    )),
    -- Hostname is DiscoverAssets's idempotency key (AGENTS.md §37).
    CONSTRAINT assets_hostname_key UNIQUE (hostname)
);
