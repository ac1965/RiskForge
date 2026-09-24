package cli

import "github.com/spf13/cobra"

func newFindingCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "finding",
		Short: "Manage findings",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List findings",
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
		&cobra.Command{
			Use:   "show <id>",
			Short: "Show a single finding",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
	)

	return cmd
}
