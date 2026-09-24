package audit

// Action names the kind of operation an Entry records (AGENTS.md §30).
// These constants are the actions §30 names explicitly; more are added by
// later phases (e.g. §20A.8's pownforge_* actions), so Action stays a
// plain string rather than a closed enum.
const (
	ActionRiskChange           = "risk_change"
	ActionPriorityChange       = "priority_change"
	ActionRemediationApproval  = "remediation_approval"
	ActionRemediationExecution = "remediation_execution"
	ActionVerification         = "verification"
	ActionExceptionCreation    = "exception_creation"
	ActionExceptionApproval    = "exception_approval"
	ActionExceptionExpiration  = "exception_expiration"
	ActionPolicyChange         = "policy_change"
)
