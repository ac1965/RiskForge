package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/remediation"
)

// manualExecutor is a placeholder application.RemediationExecutor: it
// assumes the operator running `remediation execute` already performed
// the change by hand and just records that fact. The validated,
// structured, allowlisted command execution AGENTS.md §31/§32 actually
// require is Infrastructure work for a later phase; this keeps the CLI
// usable in the meantime.
type manualExecutor struct{}

func (manualExecutor) Execute(context.Context, *remediation.Plan, remediation.DryRunInput) error {
	return nil
}

func newRemediationCommand(newService ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediation",
		Short: "Manage remediation plans",
	}

	cmd.AddCommand(
		newRemediationListCommand(newService),
		newRemediationProposeCommand(newService),
		newRemediationApproveCommand(newService),
		newRemediationPreviewCommand(newService),
		newRemediationExecuteCommand(newService),
	)

	return cmd
}

func newRemediationListCommand(newService ServiceFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List remediation plans",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			plans, err := svc.ListRemediationPlans(cmd.Context())
			if err != nil {
				return err
			}

			w := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(w, "ID\tFINDING\tACTION\tSTATUS\tPROPOSED BY\tAPPROVED BY")
			for _, p := range plans {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.FindingID, p.ActionType, p.Status, p.ProposedBy, p.ApprovedBy)
			}
			return w.Flush()
		},
	}
}

func newRemediationProposeCommand(newService ServiceFactory) *cobra.Command {
	var (
		actionType, description, proposedBy string
		rollbackCapable                     bool
		rollbackPlan, rollbackReason        string
	)

	cmd := &cobra.Command{
		Use:   "propose <finding>",
		Short: "Propose a remediation plan for a finding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			plan, err := svc.CreateRemediationPlan(cmd.Context(), remediation.Params{
				FindingID:   finding.ID(args[0]),
				ActionType:  remediation.ActionType(actionType),
				Description: description,
				ProposedBy:  proposedBy,
				Rollback: remediation.Rollback{
					Capable: rollbackCapable,
					Plan:    rollbackPlan,
					Reason:  rollbackReason,
				},
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "remediation plan %s proposed (%s)\n", plan.ID, plan.Status)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&actionType, "action-type", "", "action type, e.g. patch, upgrade, accept_risk (required)")
	flags.StringVar(&description, "description", "", "what this plan does (required)")
	flags.StringVar(&proposedBy, "proposed-by", "", "who is proposing this plan (required)")
	flags.BoolVar(&rollbackCapable, "rollback-capable", false, "whether this action can be rolled back")
	flags.StringVar(&rollbackPlan, "rollback-plan", "", "how to roll back (required if --rollback-capable)")
	flags.StringVar(&rollbackReason, "rollback-reason", "", "why rollback isn't possible (required if not --rollback-capable)")
	_ = cmd.MarkFlagRequired("action-type")
	_ = cmd.MarkFlagRequired("description")
	_ = cmd.MarkFlagRequired("proposed-by")

	return cmd
}

func newRemediationApproveCommand(newService ServiceFactory) *cobra.Command {
	var approvedBy, reason string

	cmd := &cobra.Command{
		Use:   "approve <plan>",
		Short: "Approve a proposed remediation plan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			plan, err := svc.ApproveRemediationPlan(cmd.Context(), remediation.ID(args[0]), approvedBy, reason)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "remediation plan %s approved by %s\n", plan.ID, plan.ApprovedBy)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&approvedBy, "approved-by", "", "who is approving this plan (required)")
	flags.StringVar(&reason, "reason", "", "why this plan is approved (required)")
	_ = cmd.MarkFlagRequired("approved-by")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}

func newRemediationPreviewCommand(newService ServiceFactory) *cobra.Command {
	var target string

	cmd := &cobra.Command{
		Use:   "preview <plan>",
		Short: "Dry run: preview what executing a plan would change (AGENTS.md §33)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			report, err := svc.PreviewRemediation(cmd.Context(), remediation.ID(args[0]), target)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Asset:       %s (%s)\n", report.AssetHostname, report.AssetID)
			fmt.Fprintf(out, "Finding:     %s\n", report.FindingID)
			fmt.Fprintf(out, "Action:      %s\n", report.ActionType)
			fmt.Fprintf(out, "Description: %s\n", report.Description)
			fmt.Fprintf(out, "Target:      %s\n", report.Target)
			if report.Rollback.Capable {
				fmt.Fprintf(out, "Rollback:    %s\n", report.Rollback.Plan)
			} else {
				fmt.Fprintf(out, "Rollback:    not possible (%s)\n", report.Rollback.Reason)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "what will actually change, e.g. a package name and version (required)")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func newRemediationExecuteCommand(newService ServiceFactory) *cobra.Command {
	var executedBy, reason string

	cmd := &cobra.Command{
		Use:   "execute <plan>",
		Short: "Execute an approved remediation plan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeSvc, err := newService()
			if err != nil {
				return err
			}
			defer closeSvc()

			plan, err := svc.ExecuteRemediation(cmd.Context(), remediation.ID(args[0]), executedBy, reason, time.Now(), manualExecutor{})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "remediation plan %s: %s\n", plan.ID, plan.Status)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&executedBy, "executed-by", "", "who performed (or triggered) this execution (required)")
	flags.StringVar(&reason, "reason", "", "why this plan is being executed now (required)")
	_ = cmd.MarkFlagRequired("executed-by")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}
