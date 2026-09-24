package cli

import "github.com/spf13/cobra"

func newExceptionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exception",
		Short: "Manage risk acceptance exceptions",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List exceptions",
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
	)

	return cmd
}
