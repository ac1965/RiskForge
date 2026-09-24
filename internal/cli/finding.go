package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

func newFindingCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "finding",
		Short: "Manage findings",
	}

	cmd.AddCommand(
		newFindingCorrelateCommand(newService),
		newFindingListCommand(newService),
		newFindingShowCommand(newService),
	)

	return cmd
}

// newFindingCorrelateCommand wraps correlate_findings() (AGENTS.md §26).
// Not in §27's literal list, but needed to create a Finding via the CLI
// at all.
func newFindingCorrelateCommand(newService ServiceFactory) *cobra.Command {
	var (
		assetID, vulnerabilityID, source, confidence, detectedAt string
	)

	cmd := &cobra.Command{
		Use:   "correlate",
		Short: "Record (or confirm) that a vulnerability was detected on an asset",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			detected := time.Now()
			if detectedAt != "" {
				detected, err = time.Parse(time.RFC3339, detectedAt)
				if err != nil {
					return fmt.Errorf("--detected-at: %w", err)
				}
			}

			f, err := svc.CorrelateFindings(cmd.Context(), finding.Params{
				AssetID:         asset.ID(assetID),
				VulnerabilityID: vulnerability.ID(vulnerabilityID),
				DetectionSource: source,
				DetectedAt:      detected,
				Confidence:      finding.Confidence(confidence),
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "finding %s (%s) recorded\n", f.ID, f.Status)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&assetID, "asset", "", "asset id (required)")
	flags.StringVar(&vulnerabilityID, "vulnerability", "", "vulnerability id (required)")
	flags.StringVar(&source, "source", "", "detection source, e.g. a scanner name (required)")
	flags.StringVar(&confidence, "confidence", string(finding.ConfidenceUnknown), "detection confidence")
	flags.StringVar(&detectedAt, "detected-at", "", "detection time, RFC3339 (defaults to now)")
	_ = cmd.MarkFlagRequired("asset")
	_ = cmd.MarkFlagRequired("vulnerability")
	_ = cmd.MarkFlagRequired("source")

	return cmd
}

func newFindingListCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			findings, err := svc.ListFindings(cmd.Context())
			if err != nil {
				return err
			}

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "ID\tASSET\tVULNERABILITY\tSTATUS\tCONFIDENCE\tDETECTED AT")
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					f.ID, f.AssetID, f.VulnerabilityID, f.Status, f.Confidence, f.DetectedAt.Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
}

func newFindingShowCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show a single finding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			f, err := svc.GetFinding(cmd.Context(), finding.ID(args[0]))
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ID:                %s\n", f.ID)
			fmt.Fprintf(out, "Asset:             %s\n", f.AssetID)
			fmt.Fprintf(out, "Vulnerability:     %s\n", f.VulnerabilityID)
			fmt.Fprintf(out, "Detection Source:  %s\n", f.DetectionSource)
			fmt.Fprintf(out, "Detected At:       %s\n", f.DetectedAt.Format(time.RFC3339))
			fmt.Fprintf(out, "Last Confirmed At: %s\n", f.LastConfirmedAt.Format(time.RFC3339))
			fmt.Fprintf(out, "Status:            %s\n", f.Status)
			fmt.Fprintf(out, "Confidence:        %s\n", f.Confidence)
			if f.EvidenceID != "" {
				fmt.Fprintf(out, "Evidence:          %s\n", f.EvidenceID)
			}
			return nil
		},
	}
}
