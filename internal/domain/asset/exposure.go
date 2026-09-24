package asset

// Level qualifies how an asset is reachable from an attacker's perspective
// (AGENTS.md §10). Exposure is deliberately not a single boolean.
type Level string

const (
	LevelDirect       Level = "direct"
	LevelIndirect     Level = "indirect"
	LevelInternalOnly Level = "internal_only"
	LevelRestricted   Level = "restricted"
	LevelUnknown      Level = "unknown"
)

// Valid reports whether l is one of the defined exposure levels.
func (l Level) Valid() bool {
	switch l {
	case LevelDirect, LevelIndirect, LevelInternalOnly, LevelRestricted, LevelUnknown:
		return true
	}
	return false
}

// Exposure describes whether and how an asset is reachable by an attacker
// (AGENTS.md §10). It is a property of the asset, independent of any
// vulnerability found on it.
type Exposure struct {
	InternetExposed               bool
	ExternallyAccessible          bool
	PublicIP                      bool
	ReachableFromUntrustedNetwork bool
	RemoteAccessEnabled           bool
	ServiceExposed                bool
	Level                         Level
}
