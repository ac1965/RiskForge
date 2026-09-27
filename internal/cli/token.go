package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/authn"
)

// newTokenCommand and its create/list/revoke children are not in
// AGENTS.md §27's literal list — authn (ADR 0012) postdates it — but
// bearer tokens need an entry point the same way Exception did before
// it. Per the ADR, token management is CLI-only and has no HTTP API
// counterpart: `riskforge token revoke` must keep working even if the
// API server itself is down.
func newTokenCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage HTTP API bearer tokens (ADR 0012)",
	}

	cmd.AddCommand(
		newTokenCreateCommand(newService),
		newTokenListCommand(newService),
		newTokenRevokeCommand(newService),
	)

	return cmd
}

func newTokenCreateCommand(newService ServiceFactory) *cobra.Command {
	var (
		principal string
		kind      string
		scopes    []string
		expiresIn time.Duration
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Issue a new bearer token, printing the raw value exactly once",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			var expiresAt time.Time
			if expiresIn > 0 {
				expiresAt = time.Now().Add(expiresIn)
			}

			raw, tok, err := svc.CreateAPIToken(cmd.Context(), principal, authn.Kind(kind), scopes, expiresAt)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "token: %s\n", raw)
			fmt.Fprintln(out, "This is the only time the raw token is shown — it is not stored anywhere and cannot be retrieved again. Save it now.")
			fmt.Fprintf(out, "id: %s  principal: %s  scopes: %v", tok.ID, principal, tok.Scopes)
			if tok.ExpiresAt.IsZero() {
				fmt.Fprintln(out, "  expires: never")
			} else {
				fmt.Fprintf(out, "  expires: %s\n", tok.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&principal, "principal", "", "name of the principal this token belongs to; an existing principal with this name is reused, otherwise one is created (required)")
	// Service is the default kind: most tokens minted this way are for
	// the Dashboard or another automated caller, not a human sitting at
	// this terminal (who would use --kind human).
	flags.StringVar(&kind, "kind", string(authn.KindService), "principal kind when a new principal is created: human or service")
	flags.StringSliceVar(&scopes, "scope", []string{authn.ScopeRead}, "scopes to grant this token (comma-separated): read, exception:request, exception:approve (ADR 0012/0014)")
	flags.DurationVar(&expiresIn, "expires-in", 0, "how long until the token expires, e.g. 720h for 30 days; 0 means it never expires on its own (still revocable)")
	_ = cmd.MarkFlagRequired("principal")

	return cmd
}

func newTokenListCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List bearer tokens (never shows the raw token, which is never stored)",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			tokens, err := svc.ListAPITokens(cmd.Context())
			if err != nil {
				return err
			}

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "ID\tPRINCIPAL\tSCOPES\tCREATED AT\tEXPIRES AT\tREVOKED AT\tLAST USED AT")
			for _, t := range tokens {
				fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\t%s\t%s\n",
					t.ID, t.PrincipalID, t.Scopes, t.CreatedAt.Format(time.RFC3339),
					formatOptionalTime(t.ExpiresAt), formatOptionalTime(t.RevokedAt), formatOptionalTime(t.LastUsedAt))
			}
			return w.Flush()
		},
	}
}

func newTokenRevokeCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a token immediately",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			t, err := svc.RevokeAPIToken(cmd.Context(), authn.TokenID(args[0]))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "token %s revoked at %s\n", t.ID, t.RevokedAt.Format(time.RFC3339))
			return nil
		},
	}
}

// formatOptionalTime renders t for `token list`'s nullable columns:
// authn.APIToken uses a zero time.Time to mean "unset" (see
// internal/domain/authn/token.go), which should read as "-", not
// 0001-01-01.
func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}
