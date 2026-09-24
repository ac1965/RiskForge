package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/asset"
)

func newAssetCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "asset",
		Short: "Manage assets",
	}

	cmd.AddCommand(
		newAssetDiscoverCommand(newService),
		newAssetListCommand(newService),
		newAssetInspectCommand(newService),
	)

	return cmd
}

// newAssetDiscoverCommand wraps discover_assets() (AGENTS.md §26). It is
// not one of §27's literal command list, but without it there is no way
// to get an Asset into the system via the CLI at all.
func newAssetDiscoverCommand(newService ServiceFactory) *cobra.Command {
	var (
		hostname, fqdn, osName, owner, businessUnit                   string
		assetType, environment, criticality, lifecycleState, exposure string
		internetExposed                                               bool
	)

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Register or update an asset by hostname",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			now := time.Now()
			a, err := svc.DiscoverAssets(cmd.Context(), asset.Params{
				Hostname:        hostname,
				FQDN:            fqdn,
				Type:            asset.Type(assetType),
				OperatingSystem: osName,
				Environment:     asset.Environment(environment),
				Owner:           owner,
				BusinessUnit:    businessUnit,
				Criticality:     asset.Criticality(criticality),
				Exposure: asset.Exposure{
					Level:           asset.Level(exposure),
					InternetExposed: internetExposed,
				},
				FirstSeen:      now,
				LastSeen:       now,
				LifecycleState: asset.LifecycleState(lifecycleState),
			}, now)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "asset %s (%s) discovered\n", a.ID, a.Hostname)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&hostname, "hostname", "", "asset hostname (required)")
	flags.StringVar(&fqdn, "fqdn", "", "fully qualified domain name")
	flags.StringVar(&osName, "os", "", "operating system")
	flags.StringVar(&owner, "owner", "", "asset owner")
	flags.StringVar(&businessUnit, "business-unit", "", "owning business unit")
	flags.StringVar(&assetType, "type", string(asset.TypeUnknown), "asset type")
	flags.StringVar(&environment, "environment", string(asset.EnvironmentUnknown), "environment")
	flags.StringVar(&criticality, "criticality", string(asset.CriticalityUnknown), "business criticality")
	flags.StringVar(&lifecycleState, "lifecycle-state", string(asset.LifecycleActive), "lifecycle state")
	flags.StringVar(&exposure, "exposure-level", string(asset.LevelUnknown), "exposure level")
	flags.BoolVar(&internetExposed, "internet-exposed", false, "asset is directly reachable from the internet")
	_ = cmd.MarkFlagRequired("hostname")

	return cmd
}

func newAssetListCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List assets",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			assets, err := svc.ListAssets(cmd.Context())
			if err != nil {
				return err
			}

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "ID\tHOSTNAME\tTYPE\tENVIRONMENT\tCRITICALITY\tLIFECYCLE")
			for _, a := range assets {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Hostname, a.Type, a.Environment, a.Criticality, a.LifecycleState)
			}
			return w.Flush()
		},
	}
}

func newAssetInspectCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <id>",
		Short: "Inspect a single asset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			a, err := svc.GetAsset(cmd.Context(), asset.ID(args[0]))
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ID:               %s\n", a.ID)
			fmt.Fprintf(out, "Hostname:         %s\n", a.Hostname)
			fmt.Fprintf(out, "FQDN:             %s\n", a.FQDN)
			fmt.Fprintf(out, "Type:             %s\n", a.Type)
			fmt.Fprintf(out, "OS:               %s\n", a.OperatingSystem)
			fmt.Fprintf(out, "Environment:      %s\n", a.Environment)
			fmt.Fprintf(out, "Owner:            %s\n", a.Owner)
			fmt.Fprintf(out, "Business Unit:    %s\n", a.BusinessUnit)
			fmt.Fprintf(out, "Criticality:      %s\n", a.Criticality)
			fmt.Fprintf(out, "Internet Exposed: %v\n", a.Exposure.InternetExposed)
			fmt.Fprintf(out, "Exposure Level:   %s\n", a.Exposure.Level)
			fmt.Fprintf(out, "First Seen:       %s\n", a.FirstSeen.Format(time.RFC3339))
			fmt.Fprintf(out, "Last Seen:        %s\n", a.LastSeen.Format(time.RFC3339))
			fmt.Fprintf(out, "Lifecycle State:  %s\n", a.LifecycleState)
			return nil
		},
	}
}
