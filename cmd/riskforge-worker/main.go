// Command riskforge-worker runs background jobs: data source ingestion,
// finding correlation, risk/priority recalculation, and remediation
// execution (AGENTS.md §19, §20, §25A.3). It is built as a separate binary
// so Remediation execution privileges stay isolated from the API/CLI.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "riskforge-worker: not implemented yet")
	os.Exit(1)
}
