package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

func newExceptionCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exception",
		Short: "Manage risk acceptance exceptions",
	}

	cmd.AddCommand(
		newExceptionRequestCommand(newService),
		newExceptionApproveCommand(newService),
		newExceptionRejectCommand(newService),
		newExceptionExpireCommand(newService),
		newExceptionRevokeCommand(newService),
		newExceptionListCommand(newService),
	)

	return cmd
}

// newExceptionRequestCommand and its approve/reject/expire/revoke
// siblings below are not in AGENTS.md §27's literal list ("exception
// list" is the only exception command shown there), but Exception
// (§18, Phase 4) has no entry point at all otherwise.
func newExceptionRequestCommand(newService ServiceFactory) *cobra.Command {
	var (
		findingID, reason, requestedBy, compensatingControl, expiresAt string
		maxDurationDays                                                int
	)

	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request a risk-acceptance exception for a finding",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			expires, err := time.Parse(time.RFC3339, expiresAt)
			if err != nil {
				return fmt.Errorf("--expires-at: %w", err)
			}

			var policy exception.Policy
			if maxDurationDays > 0 {
				policy.MaxDuration = time.Duration(maxDurationDays) * 24 * time.Hour
			}

			e, err := svc.RequestException(cmd.Context(), exception.Params{
				FindingID:           finding.ID(findingID),
				Reason:              reason,
				RequestedBy:         requestedBy,
				CreatedAt:           time.Now(),
				ExpiresAt:           expires,
				CompensatingControl: compensatingControl,
			}, policy)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exception %s requested, expires %s\n", e.ID, e.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&findingID, "finding", "", "finding id (required)")
	flags.StringVar(&reason, "reason", "", "justification for this exception (required)")
	flags.StringVar(&requestedBy, "requested-by", "", "who is requesting this exception (required)")
	flags.StringVar(&expiresAt, "expires-at", "", "when this exception expires, RFC3339 (required — exceptions are never permanent by default, AGENTS.md §18)")
	flags.StringVar(&compensatingControl, "compensating-control", "", "what mitigates the risk in the meantime")
	flags.IntVar(&maxDurationDays, "max-duration-days", 0, "reject requests longer than this many days (0 = no organizational cap)")
	_ = cmd.MarkFlagRequired("finding")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("requested-by")
	_ = cmd.MarkFlagRequired("expires-at")

	return cmd
}

func newExceptionApproveCommand(newService ServiceFactory) *cobra.Command {
	var approvedBy, reason string

	cmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve an exception request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			e, err := svc.ApproveException(cmd.Context(), exception.ID(args[0]), approvedBy, reason)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exception %s approved by %s\n", e.ID, e.ApprovedBy)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&approvedBy, "approved-by", "", "who is approving this exception (required)")
	flags.StringVar(&reason, "reason", "", "why this exception is approved (required)")
	_ = cmd.MarkFlagRequired("approved-by")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}

func newExceptionRejectCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "reject <id>",
		Short: "Reject an exception request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			e, err := svc.RejectException(cmd.Context(), exception.ID(args[0]))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exception %s rejected\n", e.ID)
			return nil
		},
	}
}

func newExceptionExpireCommand(newService ServiceFactory) *cobra.Command {
	var reason string

	cmd := &cobra.Command{
		Use:   "expire <id>",
		Short: "Mark an approved exception as expired",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			e, err := svc.ExpireException(cmd.Context(), exception.ID(args[0]), reason)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exception %s expired\n", e.ID)
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "reached expiry date", "context for this expiration")

	return cmd
}

func newExceptionRevokeCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an approved exception before its natural expiry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			e, err := svc.RevokeException(cmd.Context(), exception.ID(args[0]))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exception %s revoked\n", e.ID)
			return nil
		},
	}
}

func newExceptionListCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List exceptions",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			exceptions, err := svc.ListExceptions(cmd.Context())
			if err != nil {
				return err
			}

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "ID\tFINDING\tSTATUS\tREQUESTED BY\tAPPROVED BY\tEXPIRES AT")
			for _, e := range exceptions {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					e.ID, e.FindingID, e.Status, e.RequestedBy, e.ApprovedBy, e.ExpiresAt.Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
}
