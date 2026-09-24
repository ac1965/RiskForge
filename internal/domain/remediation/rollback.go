package remediation

import "fmt"

// Rollback describes how a Plan can be undone (AGENTS.md §34). It
// structurally enforces §34's requirement that an Action's inability to
// be rolled back must be stated explicitly, rather than left as an empty
// string that could just as easily mean "not filled in yet".
type Rollback struct {
	Capable bool
	// Plan describes how to undo the change. Required when Capable is
	// true.
	Plan string
	// Reason explains why the change cannot be undone. Required when
	// Capable is false.
	Reason string
}

// Validate checks that Rollback carries the field required by its
// Capable value.
func (r Rollback) Validate() error {
	if r.Capable && r.Plan == "" {
		return fmt.Errorf("remediation: rollback plan is required when rollback is capable")
	}
	if !r.Capable && r.Reason == "" {
		return fmt.Errorf("remediation: rollback reason is required when rollback is not capable")
	}
	return nil
}
