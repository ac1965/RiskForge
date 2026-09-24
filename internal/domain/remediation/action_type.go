package remediation

// ActionType is the kind of change a RemediationPlan makes (AGENTS.md
// §13). Remediation is not limited to patching.
type ActionType string

const (
	ActionPatch               ActionType = "patch"
	ActionUpgrade             ActionType = "upgrade"
	ActionConfigurationChange ActionType = "configuration_change"
	ActionDisableFeature      ActionType = "disable_feature"
	ActionDisableService      ActionType = "disable_service"
	ActionRemoveSoftware      ActionType = "remove_software"
	ActionAccessControl       ActionType = "access_control"
	ActionNetworkSegmentation ActionType = "network_segmentation"
	ActionVirtualPatch        ActionType = "virtual_patch"
	ActionCompensatingControl ActionType = "compensating_control"
	ActionTemporaryMitigation ActionType = "temporary_mitigation"
	// ActionAcceptRisk is never automatically treated as a successful
	// remediation (AGENTS.md §13): see Plan.ImpliedFindingStatus.
	ActionAcceptRisk ActionType = "accept_risk"
)

// Valid reports whether a is one of the defined action types.
func (a ActionType) Valid() bool {
	switch a {
	case ActionPatch, ActionUpgrade, ActionConfigurationChange, ActionDisableFeature,
		ActionDisableService, ActionRemoveSoftware, ActionAccessControl,
		ActionNetworkSegmentation, ActionVirtualPatch, ActionCompensatingControl,
		ActionTemporaryMitigation, ActionAcceptRisk:
		return true
	}
	return false
}
