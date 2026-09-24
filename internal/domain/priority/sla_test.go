package priority

import (
	"testing"
	"time"
)

func TestDefaultSLAPolicy(t *testing.T) {
	p := NewDefaultSLAPolicy()
	detected := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		level Level
		want  time.Time
	}{
		{LevelCritical, detected.Add(7 * 24 * time.Hour)},
		{LevelHigh, detected.Add(30 * 24 * time.Hour)},
		{LevelMedium, detected.Add(90 * 24 * time.Hour)},
		{LevelLow, detected.Add(180 * 24 * time.Hour)},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			got, err := p.Deadline(tt.level, detected)
			if err != nil {
				t.Fatalf("Deadline() unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("Deadline() = %s, want %s", got, tt.want)
			}
		})
	}

	if _, err := p.Deadline("bogus", detected); err == nil {
		t.Error("Deadline() with unconfigured level: want error, got nil")
	}
}
