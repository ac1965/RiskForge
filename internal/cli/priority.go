package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

func newPriorityCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "priority",
		Short: "Remediation priority",
	}

	cmd.AddCommand(
		newPriorityCalculateCommand(newService),
		newPriorityListCommand(newService),
	)

	return cmd
}

// newPriorityCalculateCommand wraps calculate_priority() (AGENTS.md §26).
// Not in §27's literal list — "priority list" is read-only there — but
// calculate_priority() needs some entry point, and pairing it with "risk
// assess" as a parallel write command keeps `priority list` a pure read.
func newPriorityCalculateCommand(newService ServiceFactory) *cobra.Command {
	var findingID string

	cmd := &cobra.Command{
		Use:   "calculate",
		Short: "Calculate priority (every finding with a risk assessment, or one with --finding)",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			var targets []finding.ID
			if findingID != "" {
				targets = []finding.ID{finding.ID(findingID)}
			} else {
				findings, err := svc.ListFindings(ctx)
				if err != nil {
					return err
				}
				for _, f := range findings {
					targets = append(targets, f.ID)
				}
			}

			var failures int
			for _, id := range targets {
				decision, err := svc.CalculatePriority(ctx, id)
				if err != nil {
					fmt.Fprintf(out, "finding %s: error: %v\n", id, err)
					failures++
					continue
				}
				fmt.Fprintf(out, "finding %s: priority %.1f (%s)\n", id, decision.Rank, decision.Level)
			}
			if failures > 0 {
				return fmt.Errorf("priority calculate: %d of %d findings failed", failures, len(targets))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&findingID, "finding", "", "calculate only this finding (default: every finding)")

	return cmd
}

func newPriorityListCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List prioritized findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			decisions, err := svc.ListPriorities(cmd.Context())
			if err != nil {
				return err
			}

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "FINDING\tRANK\tLEVEL\tSLA DEADLINE")
			for _, d := range decisions {
				fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\n", d.FindingID, d.Rank, d.Level, d.SLADeadline.Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
}
