// Package pownforge is the Adapter (AGENTS.md §19, §20A.1) for PownForge
// (https://github.com/ac1965/PownForge), a Scanner treated as an external
// source per AGENTS.md §20A: "PownForgeの出力形式をドメインモデルに漏ら
// さない (§19のAdapter原則を適用する)".
//
// Only normalize() is implemented so far (ADR 0018): parsing a PownForge
// RunRecord's JSON shape (as `pownforge run show <id> --format json` or
// the Web API's `GET /api/runs/{id}` return it) into
// []rawfinding.RawFinding. fetch() (actually reaching a running PownForge
// instance), validate(), and store() (persisting via
// application.Service.MatchRawFinding) are deferred to a future ADR --
// this package has no repository or network dependency and cannot fail
// except on malformed JSON, by design.
package pownforge
