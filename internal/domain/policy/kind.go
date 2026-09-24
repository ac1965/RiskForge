package policy

// Kind classifies which part of the system a policy configures
// (AGENTS.md §23). It is used to label things like an audit.Entry's
// SubjectType when a policy_change is recorded, without audit needing to
// import every policy-owning package.
type Kind string

const (
	KindRisk            Kind = "risk_policy"
	KindPriority        Kind = "priority_policy"
	KindRemediation     Kind = "remediation_policy"
	KindException       Kind = "exception_policy"
	KindAutoRemediation Kind = "auto_remediation_policy"
	KindVerification    Kind = "verification_policy"
)

// Valid reports whether k is one of the defined policy kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindRisk, KindPriority, KindRemediation, KindException, KindAutoRemediation, KindVerification:
		return true
	}
	return false
}
