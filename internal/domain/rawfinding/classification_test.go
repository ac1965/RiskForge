package rawfinding

import (
	"testing"

	"github.com/ac1965/riskforge/internal/domain/finding"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		detail     string
		confidence finding.Confidence
		want       Classification
		wantID     string
	}{
		{
			name:       "CVE in title is known vulnerability",
			title:      "[CVE-2021-36159] vsftpd version disclosure",
			confidence: finding.ConfidenceHigh,
			want:       ClassificationKnownVulnerability,
			wantID:     "CVE-2021-36159",
		},
		{
			name:       "CVE in detail is also found",
			title:      "OpenSSL Heartbleed",
			detail:     "confirmed against CVE-2014-0160",
			confidence: finding.ConfidenceMedium,
			want:       ClassificationKnownVulnerability,
			wantID:     "CVE-2014-0160",
		},
		{
			name:       "CVE id is normalized to uppercase",
			title:      "confirmed cve-2017-0144 (EternalBlue)",
			confidence: finding.ConfidenceConfirmed,
			want:       ClassificationKnownVulnerability,
			wantID:     "CVE-2017-0144",
		},
		{
			name:       "no CVE, reasonable confidence -> unknown vulnerability",
			title:      "CKV_DOCKER_8: Ensure the last USER is not root",
			confidence: finding.ConfidenceHigh,
			want:       ClassificationUnknownVulnerability,
		},
		{
			name:       "no CVE, low confidence -> unclassified",
			title:      "possible SQL injection",
			confidence: finding.ConfidenceLow,
			want:       ClassificationUnclassified,
		},
		{
			name:       "no CVE, unknown confidence -> unclassified",
			title:      "unusual response length",
			confidence: finding.ConfidenceUnknown,
			want:       ClassificationUnclassified,
		},
		{
			name:  "no CVE, empty confidence -> unclassified",
			title: "unusual response length",
			want:  ClassificationUnclassified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := RawFinding{Title: tt.title, Detail: tt.detail, Confidence: tt.confidence}
			got := Classify(rf)
			if got.Classification != tt.want {
				t.Errorf("Classify().Classification = %q, want %q", got.Classification, tt.want)
			}
			if got.VulnerabilityIdentifier != tt.wantID {
				t.Errorf("Classify().VulnerabilityIdentifier = %q, want %q", got.VulnerabilityIdentifier, tt.wantID)
			}
		})
	}
}

func TestClassificationValid(t *testing.T) {
	for _, c := range []Classification{ClassificationKnownVulnerability, ClassificationUnknownVulnerability, ClassificationUnclassified} {
		if !c.Valid() {
			t.Errorf("Classification(%q).Valid() = false, want true", c)
		}
	}
	if Classification("bogus").Valid() {
		t.Error(`Classification("bogus").Valid() = true, want false`)
	}
}
