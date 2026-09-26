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
// decided by ADR 0011 (P0-2). It implements no authentication — this is
// an intentional, temporary decision recorded in the ADR, not an
// oversight. The default bind address (127.0.0.1) is the only safeguard
// against exposing it beyond the local host; an operator who overrides
// --addr to a non-loopback address is responsible for putting
// authentication (e.g. a reverse proxy) in front of it themselves.
func newServeCommand(newService ServiceFactory, newHandler HandlerFactory) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the read-only HTTP API (no authentication yet; see ADR 0011)",
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
			fmt.Fprintf(cmd.OutOrStdout(), "listening on %s (read-only, no authentication — see ADR 0011)\n", ln.Addr())

			server := &http.Server{Handler: newHandler(svc)}
			return server.Serve(ln)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "address to bind the HTTP API to (no authentication; keep this on localhost or a trusted network, see ADR 0011)")

	return cmd
}
