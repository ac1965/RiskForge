CREATE TABLE remediation_plans (
    id               UUID PRIMARY KEY,
    finding_id       UUID NOT NULL REFERENCES findings (id),
    action_type      TEXT NOT NULL CHECK (action_type IN (
        'patch', 'upgrade', 'configuration_change', 'disable_feature',
        'disable_service', 'remove_software', 'access_control',
        'network_segmentation', 'virtual_patch', 'compensating_control',
        'temporary_mitigation', 'accept_risk'
    )),
    description      TEXT NOT NULL,
    proposed_by      TEXT NOT NULL,
    approved_by      TEXT NOT NULL DEFAULT '',
    scheduled_at     TIMESTAMPTZ,
    executed_at      TIMESTAMPTZ,
    status           TEXT NOT NULL CHECK (status IN (
        'proposed', 'approved', 'scheduled', 'in_progress', 'completed',
        'failed', 'rolled_back', 'cancelled'
    )),
    -- Rollback is a structured Capable/Plan/Reason fact (AGENTS.md §34),
    -- not a single free-text field: rollback_capable=false always carries
    -- a rollback_reason explaining why.
    rollback_capable BOOLEAN NOT NULL,
    rollback_plan    TEXT NOT NULL DEFAULT '',
    rollback_reason  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX remediation_plans_finding_id_idx ON remediation_plans (finding_id);
CREATE INDEX remediation_plans_status_idx ON remediation_plans (status);
