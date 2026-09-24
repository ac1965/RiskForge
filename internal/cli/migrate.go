package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newMigrateCommand applies pending database migrations. It operates on
// *sql.DB directly (via the migrate func supplied by cmd/riskforge), not
// through application.Service — schema migration is an operational
// concern, not a Named API.
func newMigrateCommand(migrate func() error) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending database migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := migrate(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "migrations applied")
			return nil
		},
	}
}
