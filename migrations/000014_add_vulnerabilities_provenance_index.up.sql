-- Supports MatchRawFinding's idempotency lookup for CVE-less
-- ("unknown_vulnerability", AGENTS.md §20A.2 case 2) Vulnerabilities: the
-- same (Provenance.Source, Provenance.SourceID) pair must resolve to the
-- same Vulnerability record on repeated detection (ADR 0017), the same way
-- vulnerabilities_cve_id_idx (000003) already does for CVE-backed ones.
CREATE INDEX vulnerabilities_provenance_idx ON vulnerabilities (provenance_source, provenance_source_id)
    WHERE provenance_source <> '';
