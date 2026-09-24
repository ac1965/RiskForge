package policy

import (
	"fmt"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/remediation"
)

// AutoRemediationPolicy is the auto_remediation_policy described in
// AGENTS.md §15. Its zero value denies everything: AllowAutomaticExecution
// defaults to false, so a policy has to opt in explicitly rather than
// automatic remediation being enabled by omission (§15, §47.7).
//
// This governs whether an already-approved-by-policy plan may skip the
// human remediation.Plan.Approve step; it never bypasses
// remediation.Plan's own state machine (see docs/adr/0003-remediation-safety.md),
// which still requires passing through StatusApproved before
// StatusInProgress.
type AutoRemediationPolicy struct {
	AllowAutomaticExecution bool
	AllowedAssetTypes       []asset.Type
	AllowedEnvironments     []asset.Environment
	AllowedActionTypes      []remediation.ActionType
	MaintenanceWindow       *TimeWindow
	RollbackRequired        bool
}

// Allows reports whether p permits automatic execution of an action with
// the given characteristics at time at, and if not, why.
func (p AutoRemediationPolicy) Allows(
	actionType remediation.ActionType,
	assetType asset.Type,
	environment asset.Environment,
	rollbackCapable bool,
	at time.Time,
) (bool, string) {
	if !p.AllowAutomaticExecution {
		return false, "automatic remediation is disabled by policy"
	}
	if !containsActionType(p.AllowedActionTypes, actionType) {
		return false, fmt.Sprintf("action type %q is not allowed by policy", actionType)
	}
	if !containsAssetType(p.AllowedAssetTypes, assetType) {
		return false, fmt.Sprintf("asset type %q is not allowed by policy", assetType)
	}
	if !containsEnvironment(p.AllowedEnvironments, environment) {
		return false, fmt.Sprintf("environment %q is not allowed by policy", environment)
	}
	if p.RollbackRequired && !rollbackCapable {
		return false, "policy requires rollback capability"
	}
	if p.MaintenanceWindow != nil && !p.MaintenanceWindow.Contains(at) {
		return false, "outside the configured maintenance window"
	}
	return true, ""
}

func containsActionType(list []remediation.ActionType, v remediation.ActionType) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func containsAssetType(list []asset.Type, v asset.Type) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func containsEnvironment(list []asset.Environment, v asset.Environment) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
