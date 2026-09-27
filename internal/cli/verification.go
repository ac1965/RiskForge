package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// newVerificationCommand only has "list" — Verifications are created by
// `riskforge verify` (the RunE that calls VerifyRemediation), not here;
// this is a separate noun-based command group for reading them back,
// mirroring `vulnerability`'s split between the verb that creates
// records and the noun that lists them.
func newVerificationCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verification",
		Short: "Inspect recorded verifications",
	}

	cmd.AddCommand(newVerificationListCommand(newService))

	return cmd
}

func newVerificationListCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List verifications",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			verifications, err := svc.ListVerifications(cmd.Context())
			if err != nil {
				return err
			}

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "ID\tFINDING\tMETHOD\tRESULT\tVERIFIED AT")
			for _, v := range verifications {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", v.ID, v.FindingID, v.Method, v.Result, v.VerifiedAt.Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
}
