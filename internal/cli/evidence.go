package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func newEvidenceCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Inspect evidence",
	}

	cmd.AddCommand(
		newEvidenceRecordCommand(newService),
		newEvidenceShowCommand(newService),
	)

	return cmd
}

// newEvidenceRecordCommand wraps record_evidence() (AGENTS.md §26). Not
// in §27's literal list ("evidence show" is), but verify and other flows
// need an Evidence id that has to come from somewhere.
func newEvidenceRecordCommand(newService ServiceFactory) *cobra.Command {
	var (
		evidenceType, source, assetID, findingID, location, file, contentHash string
	)

	cmd := &cobra.Command{
		Use:   "record",
		Short: "Record a piece of evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			hash := contentHash
			if file != "" {
				content, err := os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("--file: %w", err)
				}
				hash = evidence.ComputeContentHash(content)
			}
			if hash == "" {
				return fmt.Errorf("one of --file or --content-hash is required")
			}

			e, err := svc.RecordEvidence(cmd.Context(), evidence.Params{
				Type:        evidenceType,
				Source:      source,
				CollectedAt: time.Now(),
				AssetID:     asset.ID(assetID),
				FindingID:   finding.ID(findingID),
				ContentHash: hash,
				Location:    location,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "evidence %s recorded\n", e.ID)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&evidenceType, "type", "", "evidence type, e.g. detection_result, verification_result (required)")
	flags.StringVar(&source, "source", "", "where this evidence came from (required)")
	flags.StringVar(&assetID, "asset", "", "asset id this evidence is about (required)")
	flags.StringVar(&findingID, "finding", "", "finding id this evidence supports (optional)")
	flags.StringVar(&location, "location", "", "where the content is stored, e.g. a URI (required)")
	flags.StringVar(&file, "file", "", "local file to hash for --content-hash")
	flags.StringVar(&contentHash, "content-hash", "", "pre-computed content hash (alternative to --file)")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("source")
	_ = cmd.MarkFlagRequired("asset")
	_ = cmd.MarkFlagRequired("location")

	return cmd
}

func newEvidenceShowCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show a single evidence record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			e, err := svc.GetEvidence(cmd.Context(), evidence.ID(args[0]))
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ID:           %s\n", e.ID)
			fmt.Fprintf(out, "Type:         %s\n", e.Type)
			fmt.Fprintf(out, "Source:       %s\n", e.Source)
			fmt.Fprintf(out, "Collected At: %s\n", e.CollectedAt.Format(time.RFC3339))
			fmt.Fprintf(out, "Asset:        %s\n", e.AssetID)
			if e.FindingID != "" {
				fmt.Fprintf(out, "Finding:      %s\n", e.FindingID)
			}
			fmt.Fprintf(out, "Content Hash: %s\n", e.ContentHash)
			fmt.Fprintf(out, "Location:     %s\n", e.Location)
			return nil
		},
	}
}
