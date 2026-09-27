package cli

import (
	"fmt"
	"net"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/application"
)

// HandlerFactory builds the HTTP API handler from a ready
// application.Service. cmd/riskforge/main.go supplies internal/api.NewMux
// here, so internal/cli never imports internal/api directly (ADR 0011):
// internal/cli depends only on net/http (standard library) and
// internal/application.
type HandlerFactory func(*application.Service) http.Handler

// newServeCommand adds `riskforge serve`, exposing the read-only HTTP API
// decided by ADR 0011 (P0-2) and gated by ADR 0012's bearer-token
// authentication (RequireScope; see internal/api). What is still missing
// is TLS: ADR 0012 does not allow sending a Bearer token over plain
// HTTP, so the default bind address (127.0.0.1) is the only thing making
// that acceptable right now, for local curl checks and development. An
// operator who overrides --addr to a non-loopback address must not do so
// until --tls-cert/--tls-key exist (ADR 0012's own next step) or a TLS-
// terminating reverse proxy sits in front of this server.
func newServeCommand(newService ServiceFactory, newHandler HandlerFactory) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the read-only HTTP API (bearer-token auth, no TLS yet; see ADR 0011/0012)",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("serve: listen on %s: %w", addr, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "listening on %s (read-only, bearer-token auth required, plain HTTP — see ADR 0011/0012)\n", ln.Addr())

			server := &http.Server{Handler: newHandler(svc)}
			return server.Serve(ln)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "address to bind the HTTP API to (plain HTTP so far; keep this on localhost until TLS exists, see ADR 0012)")

	return cmd
}
