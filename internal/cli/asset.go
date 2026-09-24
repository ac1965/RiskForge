package cli

import "github.com/spf13/cobra"

func newAssetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "asset",
		Short: "Manage assets",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List assets",
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
		&cobra.Command{
			Use:   "inspect <id>",
			Short: "Inspect a single asset",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return errNotImplemented
			},
		},
	)

	return cmd
}
