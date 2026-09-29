package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// PownForgeNormalizer parses a PownForge RunRecord JSON payload into
// RawFindings for the given Asset and Evidence (ADR 0018/0022's
// internal/infrastructure/scanner/pownforge.Normalize). Like
// ServiceFactory/HandlerFactory, this package depends only on the
// function's signature -- cmd/riskforge/main.go supplies the concrete
// implementation, so internal/cli never imports internal/infrastructure
// directly (AGENTS.md §25 Layering).
type PownForgeNormalizer func(payload []byte, assetID asset.ID, evidenceID evidence.ID) ([]rawfinding.RawFinding, error)

// PownForgeFetcher retrieves a PownForge RunRecord's JSON from a running
// `pownforge web serve` instance (ADR 0018's
// internal/infrastructure/scanner/pownforge.Fetch), injected the same way
// as PownForgeNormalizer (ADR 0020).
type PownForgeFetcher func(ctx context.Context, baseURL, runID string) ([]byte, error)

// PownForgeEvidenceExtractor builds evidence.Params from a PownForge
// RunRecord JSON payload's own `evidence` sub-object (ADR 0018's
// internal/infrastructure/scanner/pownforge.ExtractEvidence), injected the
// same way as PownForgeNormalizer/PownForgeFetcher (ADR 0022). Its result's
// Location is always empty -- the caller (this command) fills it in, since
// only the caller knows whether payload came from a file or a network
// fetch.
type PownForgeEvidenceExtractor func(payload []byte, assetID asset.ID) (evidence.Params, error)

// newScannerCommand groups external-Scanner ingestion commands (AGENTS.md
// §20, §20A). Not in AGENTS.md §27's literal command list -- added for
// PownForge integration (ADR 0015-0022).
func newScannerCommand(newService ServiceFactory, normalizePownForge PownForgeNormalizer, fetchPownForge PownForgeFetcher, extractPownForgeEvidence PownForgeEvidenceExtractor) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scanner",
		Short: "Ingest results from an external Scanner (AGENTS.md §20A)",
	}

	cmd.AddCommand(newScannerImportPownForgeCommand(newService, normalizePownForge, fetchPownForge, extractPownForgeEvidence))

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
func newScannerImportPownForgeCommand(newService ServiceFactory, normalizePownForge PownForgeNormalizer, fetchPownForge PownForgeFetcher, extractPownForgeEvidence PownForgeEvidenceExtractor) *cobra.Command {
	var assetIDFlag, targetFlag, pownforgeURL, runID string
	var skipEvidence bool

	cmd := &cobra.Command{
		Use:   "import-pownforge [file]",
		Short: "Normalize a PownForge RunRecord (file or live fetch) and run it through the Matcher (ADR 0015-0022)",
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

			// location identifies where payload's bytes actually live, for
			// the Evidence record (ADR 0022) -- only this command knows
			// which of the two fetch strategies produced payload, so
			// Normalize/ExtractEvidence can't derive it themselves.
			var payload []byte
			var location string
			var err error
			if haveFile {
				payload, err = os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("read %s: %w", args[0], err)
				}
				if abs, err := filepath.Abs(args[0]); err == nil {
					location = "file://" + abs
				} else {
					location = "file://" + args[0]
				}
			} else {
				payload, err = fetchPownForge(cmd.Context(), pownforgeURL, runID)
				if err != nil {
					return fmt.Errorf("fetch run %s from %s: %w", runID, pownforgeURL, err)
				}
				location = strings.TrimRight(pownforgeURL, "/") + "/api/runs/" + runID
			}

			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			assetID := asset.ID(assetIDFlag)
			if targetFlag != "" {
				a, err := resolveTargetAsset(cmd.Context(), svc, targetFlag)
				if err != nil {
					return fmt.Errorf("resolve --target %s: %w", targetFlag, err)
				}
				assetID = a.ID
			}

			var evidenceID evidence.ID
			if !skipEvidence {
				evParams, err := extractPownForgeEvidence(payload, assetID)
				if err != nil {
					return fmt.Errorf("extract evidence: %w", err)
				}
				if evParams.ContentHash == "" {
					// The payload's `evidence` sub-object was missing or
					// empty (e.g. a hand-built test fixture, not a real
					// PownForge export) -- record_evidence() requires a
					// non-empty ContentHash, so there is nothing valid to
					// record; proceed without Evidence rather than fail
					// the whole import over it.
					fmt.Fprintln(cmd.ErrOrStderr(), "import-pownforge: no evidence.stdout_sha256 in payload, proceeding without Evidence")
				} else {
					evParams.Location = location
					ev, err := svc.RecordEvidence(cmd.Context(), evParams)
					if err != nil {
						return fmt.Errorf("record evidence: %w", err)
					}
					evidenceID = ev.ID
				}
			}

			rawFindings, err := normalizePownForge(payload, assetID, evidenceID)
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
	flags.BoolVar(&skipEvidence, "skip-evidence", false, "don't record an Evidence entry for this run (ADR 0022); the resulting Findings carry no EvidenceID")

	return cmd
}

// resolveTargetAsset mirrors internal/api/scanner.go's identically-named
// helper (ADR 0020/0021): discover_assets() by hostname, with `asset
// discover`'s own defaults when only a hostname is known (asset.New
// rejects a bare Hostname -- Type is required, found the hard way in ADR
// 0020). Each UI-layer package keeps its own copy rather than sharing one
// (see ADR 0021 "対象外" for why).
func resolveTargetAsset(ctx context.Context, svc *application.Service, hostname string) (*asset.Asset, error) {
	now := time.Now()
	return svc.DiscoverAssets(ctx, asset.Params{
		Hostname:       hostname,
		Type:           asset.TypeUnknown,
		Environment:    asset.EnvironmentUnknown,
		Criticality:    asset.CriticalityUnknown,
		Exposure:       asset.Exposure{Level: asset.LevelUnknown},
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: asset.LifecycleActive,
	}, now)
}
