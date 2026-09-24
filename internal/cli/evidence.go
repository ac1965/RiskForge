package cli

import "github.com/spf13/cobra"

func newEvidenceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Inspect evidence",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "show <id>",
			Short: "Show a single evidence record",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
	)

	return cmd
}
