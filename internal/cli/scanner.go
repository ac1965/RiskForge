package cli

import (
	"context"
	"fmt"
	"os"
	"time"

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

// PownForgeFetcher retrieves a PownForge RunRecord's JSON from a running
// `pownforge web serve` instance (ADR 0018's
// internal/infrastructure/scanner/pownforge.Fetch), injected the same way
// as PownForgeNormalizer (ADR 0020).
type PownForgeFetcher func(ctx context.Context, baseURL, runID string) ([]byte, error)

// newScannerCommand groups external-Scanner ingestion commands (AGENTS.md
// §20, §20A). Not in AGENTS.md §27's literal command list -- added for
// PownForge integration (ADR 0015-0020).
func newScannerCommand(newService ServiceFactory, normalizePownForge PownForgeNormalizer, fetchPownForge PownForgeFetcher) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scanner",
		Short: "Ingest results from an external Scanner (AGENTS.md §20A)",
	}

	cmd.AddCommand(newScannerImportPownForgeCommand(newService, normalizePownForge, fetchPownForge))

	return cmd
}

// newScannerImportPownForgeCommand supports two fetch() strategies
// (AGENTS.md §19/§20A.1) and two ways to identify the Asset:
//
//   - <file>: read an export already produced by PownForge (e.g.
//     `pownforge run show <id> --format json > run.json`) -- ADR 0018/0019's
//     original, simplest form.
//   - --pownforge-url + --run-id: reach a running `pownforge web serve`
//     instance directly over HTTP (ADR 0020).
//
// Exactly one of <file> or (--pownforge-url + --run-id) must be given, and
// exactly one of --asset or --target.
//
// --target <hostname> resolves to a RiskForge Asset via the existing
// discover_assets() Named API (AGENTS.md §26, `Service.DiscoverAssets`),
// the same idempotent-upsert-by-hostname path `asset discover --hostname`
// already uses -- not a new resolution mechanism, and not a decision to
// silently create Assets outside that already-sanctioned path.
// --asset <id> instead takes an existing asset.ID directly, the same
// convention `finding correlate --asset` uses, for when the Asset already
// exists under a different name.
func newScannerImportPownForgeCommand(newService ServiceFactory, normalizePownForge PownForgeNormalizer, fetchPownForge PownForgeFetcher) *cobra.Command {
	var assetIDFlag, targetFlag, pownforgeURL, runID string

	cmd := &cobra.Command{
		Use:   "import-pownforge [file]",
		Short: "Normalize a PownForge RunRecord (file or live fetch) and run it through the Matcher (ADR 0015-0020)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			haveFile := len(args) == 1
			haveFetch := pownforgeURL != "" || runID != ""
			switch {
			case haveFile && haveFetch:
				return fmt.Errorf("import-pownforge: give either <file> or --pownforge-url/--run-id, not both")
			case !haveFile && !haveFetch:
				return fmt.Errorf("import-pownforge: give either <file> or both --pownforge-url and --run-id")
			case haveFetch && (pownforgeURL == "" || runID == ""):
				return fmt.Errorf("import-pownforge: --pownforge-url and --run-id must be given together")
			}
			if (assetIDFlag == "") == (targetFlag == "") {
				return fmt.Errorf("import-pownforge: give exactly one of --asset or --target")
			}

			var payload []byte
			var err error
			if haveFile {
				payload, err = os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("read %s: %w", args[0], err)
				}
			} else {
				payload, err = fetchPownForge(cmd.Context(), pownforgeURL, runID)
				if err != nil {
					return fmt.Errorf("fetch run %s from %s: %w", runID, pownforgeURL, err)
				}
			}

			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			assetID := asset.ID(assetIDFlag)
			if targetFlag != "" {
				now := time.Now()
				// Same defaults `asset discover` (internal/cli/asset.go)
				// uses when the operator gives only --hostname: this is
				// the existing discover_assets() upsert path, not a new
				// resolution mechanism, so it must accept a bare hostname
				// the same way.
				a, err := svc.DiscoverAssets(cmd.Context(), asset.Params{
					Hostname:       targetFlag,
					Type:           asset.TypeUnknown,
					Environment:    asset.EnvironmentUnknown,
					Criticality:    asset.CriticalityUnknown,
					Exposure:       asset.Exposure{Level: asset.LevelUnknown},
					FirstSeen:      now,
					LastSeen:       now,
					LifecycleState: asset.LifecycleActive,
				}, now)
				if err != nil {
					return fmt.Errorf("resolve --target %s: %w", targetFlag, err)
				}
				assetID = a.ID
			}

			rawFindings, err := normalizePownForge(payload, assetID)
			if err != nil {
				return fmt.Errorf("normalize: %w", err)
			}

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
	flags.StringVar(&assetIDFlag, "asset", "", "RiskForge asset id these findings belong to (mutually exclusive with --target)")
	flags.StringVar(&targetFlag, "target", "", "hostname to resolve/register as the Asset via discover_assets() (mutually exclusive with --asset)")
	flags.StringVar(&pownforgeURL, "pownforge-url", "", "base URL of a running `pownforge web serve` (with --run-id, instead of [file])")
	flags.StringVar(&runID, "run-id", "", "PownForge run id to fetch (with --pownforge-url, instead of [file])")

	return cmd
}
