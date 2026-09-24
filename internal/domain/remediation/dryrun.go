package remediation

import (
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

// DryRunInput bundles the Finding and Asset a dry run is previewed
// against.
type DryRunInput struct {
	Finding *finding.Finding
	Asset   *asset.Asset
}

// DryRunReport previews what executing a Plan would do, without making
// any change (AGENTS.md §33): the target asset, the finding it addresses,
// the action to be taken, what will change, and how to undo it.
type DryRunReport struct {
	AssetID       asset.ID
	AssetHostname string
	FindingID     finding.ID
	ActionType    ActionType
	Description   string
	Target        string
	Rollback      Rollback
}

// DryRun previews executing p against in, describing target as what will
// actually change (e.g. a package name and version, a config file path).
// It performs no OS command execution: producing this preview is the only
// thing this method does (AGENTS.md §25, §33).
func (p *Plan) DryRun(in DryRunInput, target string) (*DryRunReport, error) {
	if in.Finding == nil {
		return nil, fmt.Errorf("remediation: dry run finding is required")
	}
	if in.Asset == nil {
		return nil, fmt.Errorf("remediation: dry run asset is required")
	}
	if in.Finding.ID != p.FindingID {
		return nil, fmt.Errorf("remediation: dry run finding id %q does not match plan finding id %q", in.Finding.ID, p.FindingID)
	}
	if in.Finding.AssetID != in.Asset.ID {
		return nil, fmt.Errorf("remediation: dry run finding asset id %q does not match asset id %q", in.Finding.AssetID, in.Asset.ID)
	}
	if target == "" {
		return nil, fmt.Errorf("remediation: dry run target is required")
	}

	return &DryRunReport{
		AssetID:       in.Asset.ID,
		AssetHostname: in.Asset.Hostname,
		FindingID:     p.FindingID,
		ActionType:    p.ActionType,
		Description:   p.Description,
		Target:        target,
		Rollback:      p.Rollback,
	}, nil
}
