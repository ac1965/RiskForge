package policy

import (
	"testing"
	"time"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/remediation"
)

// TestZeroValueDeniesByDefault is the AGENTS.md §15 / §47.7 invariant:
// automatic remediation must be disabled unless a policy explicitly opts
// in.
func TestZeroValueDeniesByDefault(t *testing.T) {
	var p AutoRemediationPolicy

	allowed, reason := p.Allows(remediation.ActionPatch, asset.TypeServer, asset.EnvironmentProduction, true, time.Now())
	if allowed {
		t.Error("zero-value AutoRemediationPolicy.Allows() = true, want false")
	}
	if reason == "" {
		t.Error("Allows() returned no reason for denial")
	}
}

func permissivePolicy() AutoRemediationPolicy {
	return AutoRemediationPolicy{
		AllowAutomaticExecution: true,
		AllowedAssetTypes:       []asset.Type{asset.TypeServer},
		AllowedEnvironments:     []asset.Environment{asset.EnvironmentStaging},
		AllowedActionTypes:      []remediation.ActionType{remediation.ActionPatch},
		RollbackRequired:        true,
	}
}

func TestAllows(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		policy          AutoRemediationPolicy
		actionType      remediation.ActionType
		assetType       asset.Type
		environment     asset.Environment
		rollbackCapable bool
		at              time.Time
		want            bool
	}{
		{
			name: "fully permitted", policy: permissivePolicy(),
			actionType: remediation.ActionPatch, assetType: asset.TypeServer,
			environment: asset.EnvironmentStaging, rollbackCapable: true, at: now,
			want: true,
		},
		{
			name: "action type not allowed", policy: permissivePolicy(),
			actionType: remediation.ActionRemoveSoftware, assetType: asset.TypeServer,
			environment: asset.EnvironmentStaging, rollbackCapable: true, at: now,
			want: false,
		},
		{
			name: "asset type not allowed", policy: permissivePolicy(),
			actionType: remediation.ActionPatch, assetType: asset.TypeContainer,
			environment: asset.EnvironmentStaging, rollbackCapable: true, at: now,
			want: false,
		},
		{
			name: "environment not allowed", policy: permissivePolicy(),
			actionType: remediation.ActionPatch, assetType: asset.TypeServer,
			environment: asset.EnvironmentProduction, rollbackCapable: true, at: now,
			want: false,
		},
		{
			name: "rollback required but not capable", policy: permissivePolicy(),
			actionType: remediation.ActionPatch, assetType: asset.TypeServer,
			environment: asset.EnvironmentStaging, rollbackCapable: false, at: now,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := tt.policy.Allows(tt.actionType, tt.assetType, tt.environment, tt.rollbackCapable, tt.at)
			if got != tt.want {
				t.Errorf("Allows() = %v (%s), want %v", got, reason, tt.want)
			}
			if !got && reason == "" {
				t.Error("Allows() denied with no reason")
			}
		})
	}
}

func TestMaintenanceWindow(t *testing.T) {
	p := permissivePolicy()
	window := TimeWindow{
		Start: time.Date(2026, 1, 1, 22, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 1, 2, 2, 0, 0, 0, time.UTC),
	}
	p.MaintenanceWindow = &window

	inside := time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC)
	outside := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if allowed, _ := p.Allows(remediation.ActionPatch, asset.TypeServer, asset.EnvironmentStaging, true, inside); !allowed {
		t.Error("Allows() inside maintenance window = false, want true")
	}
	if allowed, _ := p.Allows(remediation.ActionPatch, asset.TypeServer, asset.EnvironmentStaging, true, outside); allowed {
		t.Error("Allows() outside maintenance window = true, want false")
	}
}
