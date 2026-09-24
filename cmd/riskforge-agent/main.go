// Command riskforge-agent runs on managed assets to collect inventory and
// scan data (AGENTS.md §20, §25A.3). It is built as a separate binary so
// Scanner privileges never share a process with Remediation execution.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "riskforge-agent: not implemented yet")
	os.Exit(1)
}
