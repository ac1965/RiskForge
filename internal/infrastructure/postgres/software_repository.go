package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/software"
)

// SoftwareRepository implements application.SoftwareRepository against
// PostgreSQL.
type SoftwareRepository struct {
	db *sql.DB
}

// NewSoftwareRepository returns a SoftwareRepository backed by db.
func NewSoftwareRepository(db *sql.DB) *SoftwareRepository {
	return &SoftwareRepository{db: db}
}

const softwareColumns = `
	id, asset_id, vendor, product, version, architecture,
	package_manager, install_path, cpe, purl, first_seen, last_seen`

// Save inserts i, or updates it in place if i.ID already exists.
func (r *SoftwareRepository) Save(ctx context.Context, i *software.Installation) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO software_installations (`+softwareColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id) DO UPDATE SET
			asset_id = EXCLUDED.asset_id,
			vendor = EXCLUDED.vendor,
			product = EXCLUDED.product,
			version = EXCLUDED.version,
			architecture = EXCLUDED.architecture,
			package_manager = EXCLUDED.package_manager,
			install_path = EXCLUDED.install_path,
			cpe = EXCLUDED.cpe,
			purl = EXCLUDED.purl,
			first_seen = EXCLUDED.first_seen,
			last_seen = EXCLUDED.last_seen
	`,
		i.ID, i.AssetID, i.Vendor, i.Product, i.Version, i.Architecture,
		i.PackageManager, i.InstallPath, i.CPE, i.PURL, i.FirstSeen, i.LastSeen,
	)
	if err != nil {
		return fmt.Errorf("postgres: save software installation %s: %w", i.ID, err)
	}
	return nil
}

func scanSoftware(row rowScanner) (*software.Installation, error) {
	var i software.Installation
	err := row.Scan(
		&i.ID, &i.AssetID, &i.Vendor, &i.Product, &i.Version, &i.Architecture,
		&i.PackageManager, &i.InstallPath, &i.CPE, &i.PURL, &i.FirstSeen, &i.LastSeen,
	)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// FindByNaturalKey returns the Installation matching (assetID, vendor,
// product, version), or (nil, nil) if none exists. This is
// InventoryAsset's idempotency key (AGENTS.md §37).
func (r *SoftwareRepository) FindByNaturalKey(ctx context.Context, assetID asset.ID, vendor, product, version string) (*software.Installation, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+softwareColumns+` FROM software_installations
		WHERE asset_id = $1 AND vendor = $2 AND product = $3 AND version = $4
	`, assetID, vendor, product, version)

	i, err := scanSoftware(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find software installation: %w", err)
	}
	return i, nil
}
