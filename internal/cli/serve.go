package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/rawfinding"
)

// HandlerFactory builds the HTTP API handler from a ready
// application.Service. cmd/riskforge/main.go supplies internal/api.NewMux
// here, so internal/cli never imports internal/api directly (ADR 0011):
// internal/cli depends only on net/http (standard library) and
// internal/application. The second/third parameters use the same raw,
// unnamed function type PownForgeNormalizer/PownForgeFetcher alias in
// scanner.go (ADR 0018/0020) -- see api.NewMux's doc comment (ADR 0021)
// for why this signature must stay the literal unnamed type rather than
// referencing either package's named alias.
type HandlerFactory func(
	*application.Service,
	func(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error),
	func(ctx context.Context, baseURL, runID string) ([]byte, error),
) http.Handler

// newServeCommand adds `riskforge serve`, exposing the HTTP API decided
// by ADR 0011 (P0-2, read-only) and ADR 0014 (P0-3, the Exception
// workflow's write endpoints), gated by ADR 0012's bearer-token
// authentication (RequireScope; see internal/api). ADR 0012 does not
// allow sending a Bearer token over plain HTTP off the local machine, so
// binding anywhere other than localhost without --tls-cert/--tls-key (or
// a TLS-terminating reverse proxy sitting in front, with this command
// itself still bound to localhost) is refused outright rather than left
// as a foot-gun.
func newServeCommand(newService ServiceFactory, newHandler HandlerFactory, normalizePownForge PownForgeNormalizer, fetchPownForge PownForgeFetcher) *cobra.Command {
	var addr, tlsCert, tlsKey string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the HTTP API (bearer-token auth; TLS required off localhost; see ADR 0011/0012/0014)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if (tlsCert == "") != (tlsKey == "") {
				return fmt.Errorf("serve: --tls-cert and --tls-key must be given together")
			}
			tlsEnabled := tlsCert != ""

			if !tlsEnabled && !isLoopbackAddr(addr) {
				return fmt.Errorf(
					"serve: refusing to bind %s without TLS: a Bearer token must not travel over plain HTTP off the local machine (ADR 0012). "+
						"Bind to localhost, pass --tls-cert/--tls-key, or put a TLS-terminating reverse proxy in front and keep this bound to localhost",
					addr,
				)
			}

			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("serve: listen on %s: %w", addr, err)
			}
			server := &http.Server{Handler: newHandler(svc, normalizePownForge, fetchPownForge)}

			if tlsEnabled {
				fmt.Fprintf(cmd.OutOrStdout(), "listening on %s (bearer-token auth required, TLS)\n", ln.Addr())
				return server.ServeTLS(ln, tlsCert, tlsKey)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "listening on %s (bearer-token auth required, plain HTTP — localhost only, see ADR 0012)\n", ln.Addr())
			return server.Serve(ln)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&addr, "addr", "127.0.0.1:8080", "address to bind the HTTP API to; binding anywhere other than localhost requires --tls-cert/--tls-key (ADR 0012)")
	flags.StringVar(&tlsCert, "tls-cert", "", "TLS certificate file (PEM); enables HTTPS, required together with --tls-key")
	flags.StringVar(&tlsKey, "tls-key", "", "TLS private key file (PEM); required together with --tls-cert")

	return cmd
}

// isLoopbackAddr reports whether addr's host part (as passed to --addr,
// e.g. "127.0.0.1:8080" or "localhost:8080") refers only to the local
// machine. A bare ":8080" has an empty host, meaning "every interface" —
// that is a wildcard bind, not loopback, even though it happens to
// include loopback among the interfaces it listens on.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
