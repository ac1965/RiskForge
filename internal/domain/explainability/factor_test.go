package explainability

import "testing"

func TestFactorValidate(t *testing.T) {
	tests := []struct {
		name    string
		factor  Factor
		wantErr bool
	}{
		{name: "valid", factor: Factor{Name: "cvss", Value: "9.8", Reason: "high severity"}},
		{name: "missing name", factor: Factor{Reason: "high severity"}, wantErr: true},
		{name: "missing reason", factor: Factor{Name: "cvss", Value: "9.8"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.factor.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
		})
	}
}
