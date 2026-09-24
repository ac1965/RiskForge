package exception

import (
	"testing"
	"time"
)

func TestPolicyValidate(t *testing.T) {
	p := validParams()
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	zeroPolicy := Policy{}
	if err := zeroPolicy.Validate(e); err != nil {
		t.Errorf("zero-value Policy.Validate() unexpected error: %v", err)
	}

	strict := Policy{MaxDuration: 30 * 24 * time.Hour}
	if err := strict.Validate(e); err == nil {
		t.Error("strict Policy.Validate() with a 90-day exception: want error, got nil")
	}

	lenient := Policy{MaxDuration: 180 * 24 * time.Hour}
	if err := lenient.Validate(e); err != nil {
		t.Errorf("lenient Policy.Validate() unexpected error: %v", err)
	}
}
