// Package cli wires the riskforge command-line interface (AGENTS.md §27).
//
// Commands call into internal/application; they must not reach into
// internal/domain or internal/infrastructure directly (AGENTS.md §25).
package cli

import (
	"github.com/spf13/cobra"
)

// version is set via -ldflags at build time.
var version = "dev"

// NewRootCommand builds the root "riskforge" command.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "riskforge",
		Short:         "Vulnerability & Exposure Management Platform",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	root.AddCommand(
		newAssetCommand(),
		newFindingCommand(),
		newRiskCommand(),
		newPriorityCommand(),
		newRemediationCommand(),
		newVerifyCommand(),
		newEvidenceCommand(),
		newExceptionCommand(),
	)

	return root
}
