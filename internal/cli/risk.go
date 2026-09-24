package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

func newRiskCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Risk assessment",
	}

	cmd.AddCommand(newRiskAssessCommand(newService))

	return cmd
}

func newRiskAssessCommand(newService ServiceFactory) *cobra.Command {
	var findingID string

	cmd := &cobra.Command{
		Use:   "assess",
		Short: "Run a risk assessment (all findings, or one with --finding)",
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
				assessment, err := svc.AssessRisk(ctx, id)
				if err != nil {
					fmt.Fprintf(out, "finding %s: error: %v\n", id, err)
					failures++
					continue
				}
				fmt.Fprintf(out, "finding %s: risk %.1f (%s)\n", id, assessment.Score, assessment.Level)
			}
			if failures > 0 {
				return fmt.Errorf("risk assess: %d of %d findings failed", failures, len(targets))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&findingID, "finding", "", "assess only this finding (default: every finding)")

	return cmd
}
