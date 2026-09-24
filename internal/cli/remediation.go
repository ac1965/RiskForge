package cli

import "github.com/spf13/cobra"

func newRemediationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediation",
		Short: "Manage remediation plans",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List remediation plans",
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
		&cobra.Command{
			Use:   "propose <finding>",
			Short: "Propose a remediation plan for a finding",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
	)

	return cmd
}
