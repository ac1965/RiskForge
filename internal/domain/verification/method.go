package verification

// Method is how a Verification was performed (AGENTS.md §16).
type Method string

const (
	MethodVersionCheck       Method = "version_check"
	MethodConfigurationCheck Method = "configuration_check"
	MethodPackageCheck       Method = "package_check"
	MethodScannerRescan      Method = "scanner_rescan"
	MethodServiceCheck       Method = "service_check"
)

// Valid reports whether m is one of the defined verification methods.
func (m Method) Valid() bool {
	switch m {
	case MethodVersionCheck, MethodConfigurationCheck, MethodPackageCheck,
		MethodScannerRescan, MethodServiceCheck:
		return true
	}
	return false
}
