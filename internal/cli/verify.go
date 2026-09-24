package cli

import "github.com/spf13/cobra"

func newVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <finding>",
		Short: "Verify remediation of a finding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented
		},
	}
}
