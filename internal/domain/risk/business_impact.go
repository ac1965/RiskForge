package risk

// BusinessImpact captures the business-context inputs to a risk
// assessment (AGENTS.md §11): data that should come from a CMDB, asset
// register, or business owner, never inferred from technical scan data.
// It is deliberately richer than, and independent of, asset.Criticality.
type BusinessImpact struct {
	BusinessCriticality        string
	DataClassification         string
	ServiceCriticality         string
	AvailabilityRequirement    string
	ConfidentialityRequirement string
	IntegrityRequirement       string
}
