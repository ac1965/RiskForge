package policy

import "testing"

func TestKindValid(t *testing.T) {
	valid := []Kind{
		KindRisk, KindPriority, KindRemediation,
		KindException, KindAutoRemediation, KindVerification,
	}
	for _, k := range valid {
		if !k.Valid() {
			t.Errorf("Kind(%q).Valid() = false, want true", k)
		}
	}

	if Kind("bogus_policy").Valid() {
		t.Error(`Kind("bogus_policy").Valid() = true, want false`)
	}
}
