// Package cli wires the riskforge command-line interface (AGENTS.md §27).
//
// Commands call into internal/application; they must not reach into
// internal/domain business logic or internal/infrastructure directly
// (AGENTS.md §25). Domain value types (Params structs, enum constants)
// are used only to build request data for Application calls.
package cli

import (
	"github.com/spf13/cobra"
)

// version is set via -ldflags at build time.
var version = "dev"

// NewRootCommand builds the root "riskforge" command. newService lazily
// connects to persistence for every command except migrate, which uses
// migrate directly.
func NewRootCommand(newService ServiceFactory, migrate func() error) *cobra.Command {
	root := &cobra.Command{
		Use:          "riskforge",
		Short:        "Vulnerability & Exposure Management Platform",
		Version:      version,
		SilenceUsage: true,
		// cmd/riskforge's main() prints the error Execute() returns;
		// letting cobra also print it here would duplicate the message.
		SilenceErrors: true,
	}

	root.AddCommand(
		newMigrateCommand(migrate),
		newAssetCommand(newService),
		newVulnerabilityCommand(newService),
		newFindingCommand(newService),
		newRiskCommand(newService),
		newPriorityCommand(newService),
		newRemediationCommand(newService),
		newVerifyCommand(newService),
		newEvidenceCommand(newService),
		newExceptionCommand(newService),
	)

	return root
}
