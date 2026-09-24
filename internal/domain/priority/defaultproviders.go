package priority

// FromVulnerabilityRemediationProvider is a RemediationAvailabilityProvider
// that reads directly from the Vulnerability already attached to the
// Input, with no external lookups.
type FromVulnerabilityRemediationProvider struct{}

// RemediationAvailability returns in.Vulnerability.RemediationAvailable.
func (FromVulnerabilityRemediationProvider) RemediationAvailability(in Input) (bool, error) {
	return in.Vulnerability.RemediationAvailable, nil
}

// StaticBusinessConstraintsProvider always returns the same
// BusinessConstraints, regardless of Input. It is a placeholder for use
// until a change-management adapter is wired in.
type StaticBusinessConstraintsProvider struct {
	Constraints BusinessConstraints
}

// BusinessConstraints returns p.Constraints.
func (p StaticBusinessConstraintsProvider) BusinessConstraints(Input) (BusinessConstraints, error) {
	return p.Constraints, nil
}
