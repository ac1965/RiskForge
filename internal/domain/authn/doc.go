// Package authn models the minimal identity and bearer-token
// authentication RiskForge's HTTP API needs (docs/adr/0012-http-api-authentication.md).
//
// It is deliberately not a general-purpose IAM system (AGENTS.md §48): a
// Principal is "who", an APIToken is "what that principal is currently
// allowed to do, and until when". Authorization/scope-name design beyond
// the single "read" scope P0-2 needs is out of scope until a PR actually
// adds a write endpoint.
package authn
