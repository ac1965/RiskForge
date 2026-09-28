package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// PownForgeNormalizer parses a PownForge RunRecord JSON payload into
// RawFindings for the given Asset (ADR 0018's
// internal/infrastructure/scanner/pownforge.Normalize). Like
// ServiceFactory/HandlerFactory, this package depends only on the
// function's signature -- cmd/riskforge/main.go supplies the concrete
// implementation, so internal/cli never imports internal/infrastructure
// directly (AGENTS.md §25 Layering).
type PownForgeNormalizer func(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error)

// newScannerCommand groups external-Scanner ingestion commands (AGENTS.md
// §20, §20A). Not in AGENTS.md §27's literal command list -- added for
// PownForge integration (ADR 0015-0019).
func newScannerCommand(newService ServiceFactory, normalizePownForge PownForgeNormalizer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scanner",
		Short: "Ingest results from an external Scanner (AGENTS.md §20A)",
	}

	cmd.AddCommand(newScannerImportPownForgeCommand(newService, normalizePownForge))

	return cmd
}

// newScannerImportPownForgeCommand is this ADR's "fetch()": the simplest
// possible one, reading a file already exported from PownForge (e.g.
// `pownforge run show <id> --format json > run.json`) rather than reaching
// a running PownForge instance over the network -- deciding on that
// transport, and on resolving PownForge's target name to a RiskForge
// Asset automatically, are both deferred to a future ADR (ADR 0019
// "対象外"). --asset takes an existing RiskForge asset.ID directly, the
// same convention `finding correlate --asset` already uses.
func newScannerImportPownForgeCommand(newService ServiceFactory, normalizePownForge PownForgeNormalizer) *cobra.Command {
	var assetIDFlag string

	cmd := &cobra.Command{
		Use:   "import-pownforge <file>",
		Short: "Normalize a PownForge RunRecord JSON export and run it through the Matcher (ADR 0015-0019)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}

			rawFindings, err := normalizePownForge(payload, asset.ID(assetIDFlag))
			if err != nil {
				return fmt.Errorf("normalize %s: %w", args[0], err)
			}

			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "TITLE\tOUTCOME\tFINDING")
			for _, rf := range rawFindings {
				f, outcome, err := svc.MatchRawFinding(cmd.Context(), rf)
				if err != nil {
					return fmt.Errorf("match %q: %w", rf.Title, err)
				}
				findingID := "-"
				if f != nil {
					findingID = string(f.ID)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", rf.Title, outcome, findingID)
			}
			return w.Flush()
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&assetIDFlag, "asset", "", "RiskForge asset id these findings belong to (required; see `riskforge asset list`)")
	_ = cmd.MarkFlagRequired("asset")

	return cmd
}
