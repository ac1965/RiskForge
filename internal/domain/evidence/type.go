package evidence

// Type categorizes what an Evidence record contains (AGENTS.md §17). The
// list in §17 is explicitly non-exhaustive ("...など"), so Type is left as
// an open string rather than a closed enum: these constants are common
// values, not the only allowed ones.
const (
	TypeDetectionResult      = "detection_result"
	TypePackageInfo          = "package_info"
	TypeVersionInfo          = "version_info"
	TypeConfiguration        = "configuration"
	TypeRemediationExecution = "remediation_execution"
	TypeVerificationResult   = "verification_result"
)
