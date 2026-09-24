package asset

// Type classifies what kind of asset this is (AGENTS.md §4 asset_type).
type Type string

const (
	TypeServer         Type = "server"
	TypeWorkstation    Type = "workstation"
	TypeLaptop         Type = "laptop"
	TypeContainer      Type = "container"
	TypeVirtualMachine Type = "virtual_machine"
	TypeCloudInstance  Type = "cloud_instance"
	TypeNetworkDevice  Type = "network_device"
	TypeDatabase       Type = "database"
	TypeApplication    Type = "application"
	TypeMobileDevice   Type = "mobile_device"
	TypeIoT            Type = "iot"
	TypeUnknown        Type = "unknown"
)

// Valid reports whether t is one of the defined asset types.
func (t Type) Valid() bool {
	switch t {
	case TypeServer, TypeWorkstation, TypeLaptop, TypeContainer, TypeVirtualMachine,
		TypeCloudInstance, TypeNetworkDevice, TypeDatabase, TypeApplication,
		TypeMobileDevice, TypeIoT, TypeUnknown:
		return true
	}
	return false
}

// Environment classifies where the asset runs (AGENTS.md §4 environment).
type Environment string

const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentManagement  Environment = "management"
	EnvironmentUnknown     Environment = "unknown"
)

// Valid reports whether e is one of the defined environments.
func (e Environment) Valid() bool {
	switch e {
	case EnvironmentProduction, EnvironmentStaging, EnvironmentDevelopment,
		EnvironmentTest, EnvironmentManagement, EnvironmentUnknown:
		return true
	}
	return false
}

// Criticality is the asset's business importance (AGENTS.md §4 criticality).
// It is set from business context (CMDB, asset register, business owner),
// never derived from CVSS or other technical severity (AGENTS.md §11, §44
// Invariant 5).
type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
	CriticalityUnknown  Criticality = "unknown"
)

// Valid reports whether c is one of the defined criticality levels.
func (c Criticality) Valid() bool {
	switch c {
	case CriticalityCritical, CriticalityHigh, CriticalityMedium, CriticalityLow, CriticalityUnknown:
		return true
	}
	return false
}

// LifecycleState is the asset's position in its own lifecycle
// (AGENTS.md §4 lifecycle_state).
type LifecycleState string

const (
	LifecycleActive         LifecycleState = "active"
	LifecycleInactive       LifecycleState = "inactive"
	LifecycleDecommissioned LifecycleState = "decommissioned"
	LifecycleUnknown        LifecycleState = "unknown"
)

// Valid reports whether s is one of the defined lifecycle states.
func (s LifecycleState) Valid() bool {
	switch s {
	case LifecycleActive, LifecycleInactive, LifecycleDecommissioned, LifecycleUnknown:
		return true
	}
	return false
}
