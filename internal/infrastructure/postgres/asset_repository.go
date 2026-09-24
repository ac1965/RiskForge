package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ac1965/riskforge/internal/domain/asset"
)

// AssetRepository implements application.AssetRepository against
// PostgreSQL.
type AssetRepository struct {
	db *sql.DB
}

// NewAssetRepository returns an AssetRepository backed by db.
func NewAssetRepository(db *sql.DB) *AssetRepository {
	return &AssetRepository{db: db}
}

const assetColumns = `
	id, hostname, fqdn, ip_addresses, mac_addresses, asset_type,
	operating_system, environment, owner, business_unit, criticality,
	exposure_internet_exposed, exposure_externally_accessible,
	exposure_public_ip, exposure_reachable_from_untrusted_network,
	exposure_remote_access_enabled, exposure_service_exposed,
	exposure_level, first_seen, last_seen, lifecycle_state`

// Save inserts a, or updates it in place if a.ID already exists.
func (r *AssetRepository) Save(ctx context.Context, a *asset.Asset) error {
	ipAddresses, err := jsonStrings(a.IPAddresses)
	if err != nil {
		return fmt.Errorf("postgres: marshal ip addresses: %w", err)
	}
	macAddresses, err := jsonStrings(a.MACAddresses)
	if err != nil {
		return fmt.Errorf("postgres: marshal mac addresses: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO assets (`+assetColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			fqdn = EXCLUDED.fqdn,
			ip_addresses = EXCLUDED.ip_addresses,
			mac_addresses = EXCLUDED.mac_addresses,
			asset_type = EXCLUDED.asset_type,
			operating_system = EXCLUDED.operating_system,
			environment = EXCLUDED.environment,
			owner = EXCLUDED.owner,
			business_unit = EXCLUDED.business_unit,
			criticality = EXCLUDED.criticality,
			exposure_internet_exposed = EXCLUDED.exposure_internet_exposed,
			exposure_externally_accessible = EXCLUDED.exposure_externally_accessible,
			exposure_public_ip = EXCLUDED.exposure_public_ip,
			exposure_reachable_from_untrusted_network = EXCLUDED.exposure_reachable_from_untrusted_network,
			exposure_remote_access_enabled = EXCLUDED.exposure_remote_access_enabled,
			exposure_service_exposed = EXCLUDED.exposure_service_exposed,
			exposure_level = EXCLUDED.exposure_level,
			first_seen = EXCLUDED.first_seen,
			last_seen = EXCLUDED.last_seen,
			lifecycle_state = EXCLUDED.lifecycle_state
	`,
		a.ID, a.Hostname, a.FQDN, ipAddresses, macAddresses, a.Type,
		a.OperatingSystem, a.Environment, a.Owner, a.BusinessUnit, a.Criticality,
		a.Exposure.InternetExposed, a.Exposure.ExternallyAccessible,
		a.Exposure.PublicIP, a.Exposure.ReachableFromUntrustedNetwork,
		a.Exposure.RemoteAccessEnabled, a.Exposure.ServiceExposed,
		a.Exposure.Level, a.FirstSeen, a.LastSeen, a.LifecycleState,
	)
	if err != nil {
		return fmt.Errorf("postgres: save asset %s: %w", a.ID, err)
	}
	return nil
}

func scanAsset(row rowScanner) (*asset.Asset, error) {
	var a asset.Asset
	var ipAddresses, macAddresses []byte

	err := row.Scan(
		&a.ID, &a.Hostname, &a.FQDN, &ipAddresses, &macAddresses, &a.Type,
		&a.OperatingSystem, &a.Environment, &a.Owner, &a.BusinessUnit, &a.Criticality,
		&a.Exposure.InternetExposed, &a.Exposure.ExternallyAccessible,
		&a.Exposure.PublicIP, &a.Exposure.ReachableFromUntrustedNetwork,
		&a.Exposure.RemoteAccessEnabled, &a.Exposure.ServiceExposed,
		&a.Exposure.Level, &a.FirstSeen, &a.LastSeen, &a.LifecycleState,
	)
	if err != nil {
		return nil, err
	}

	if a.IPAddresses, err = scanStrings(ipAddresses); err != nil {
		return nil, err
	}
	if a.MACAddresses, err = scanStrings(macAddresses); err != nil {
		return nil, err
	}
	return &a, nil
}

// FindByID returns the Asset with the given id, or (nil, nil) if none
// exists.
func (r *AssetRepository) FindByID(ctx context.Context, id asset.ID) (*asset.Asset, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE id = $1`, id)
	a, err := scanAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find asset %s: %w", id, err)
	}
	return a, nil
}

// FindByHostname returns the Asset with the given hostname, or (nil, nil)
// if none exists. This is DiscoverAssets's idempotency key (AGENTS.md
// §37).
func (r *AssetRepository) FindByHostname(ctx context.Context, hostname string) (*asset.Asset, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE hostname = $1`, hostname)
	a, err := scanAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find asset by hostname %q: %w", hostname, err)
	}
	return a, nil
}
