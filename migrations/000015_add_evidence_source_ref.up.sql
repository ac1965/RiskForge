-- ADR 0015 added Evidence.SourceRef (AGENTS.md §20A.4) to the domain type
-- and ADR 0004's addendum, but the column was never actually added here or
-- wired into internal/infrastructure/postgres/evidence_repository.go --
-- this closes that gap (found while implementing ADR 0018).
ALTER TABLE evidence ADD COLUMN source_ref TEXT NOT NULL DEFAULT '';
