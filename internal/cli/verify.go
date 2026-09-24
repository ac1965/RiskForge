package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/verification"
)

func newVerifyCommand(newService ServiceFactory) *cobra.Command {
	var (
		method, result, evidenceID, performedBy, reason string
	)

	cmd := &cobra.Command{
		Use:   "verify <finding>",
		Short: "Verify remediation of a finding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			v, err := svc.VerifyRemediation(cmd.Context(), verification.Params{
				FindingID:  finding.ID(args[0]),
				Method:     verification.Method(method),
				VerifiedAt: time.Now(),
				Result:     verification.Result(result),
				EvidenceID: evidence.ID(evidenceID),
			}, performedBy, reason)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "verification %s: %s (%s)\n", v.ID, v.Result, v.Method)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&method, "method", "", "verification method, e.g. version_check, scanner_rescan (required)")
	flags.StringVar(&result, "result", "", "pass, fail, or inconclusive (required)")
	flags.StringVar(&evidenceID, "evidence", "", "evidence id backing this result (required)")
	flags.StringVar(&performedBy, "performed-by", "", "who performed this verification (required)")
	flags.StringVar(&reason, "reason", "", "context for this verification (required)")
	_ = cmd.MarkFlagRequired("method")
	_ = cmd.MarkFlagRequired("result")
	_ = cmd.MarkFlagRequired("evidence")
	_ = cmd.MarkFlagRequired("performed-by")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}
