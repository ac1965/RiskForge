package verification

// Result is the outcome of a Verification attempt (AGENTS.md §16,
// §20A.6.1). ResultInconclusive is kept distinct from ResultFail: a check
// that could not run (e.g. the asset was unreachable) is not evidence
// that the vulnerability is still present.
type Result string

const (
	ResultPass         Result = "pass"
	ResultFail         Result = "fail"
	ResultInconclusive Result = "inconclusive"
)

// Valid reports whether r is one of the defined results.
func (r Result) Valid() bool {
	switch r {
	case ResultPass, ResultFail, ResultInconclusive:
		return true
	}
	return false
}
