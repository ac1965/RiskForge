// Command riskforge is the CLI / API entrypoint (AGENTS.md §25A.2).
package main

import (
	"fmt"
	"os"

	"github.com/ac1965/riskforge/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
