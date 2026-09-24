package cli

import "github.com/spf13/cobra"

func newPriorityCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "priority",
		Short: "Remediation priority",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List prioritized findings",
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
	)

	return cmd
}
