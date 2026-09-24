// Package datasource implements external data source adapters (AGENTS.md
// §19: NVD, CISA KEV, OSV, vendor advisories, internal inventory).
//
// Each adapter separates fetch(), normalize(), validate(), and store() so
// that upstream response formats never leak into the domain model.
package datasource
