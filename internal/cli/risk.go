package cli

import "github.com/spf13/cobra"

func newRiskCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Risk assessment",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "assess",
			Short: "Run a risk assessment",
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
	)

	return cmd
}
