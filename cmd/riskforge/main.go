// Command riskforge is the CLI / API entrypoint (AGENTS.md §25A.2).
//
// This file is the composition root: it is the one place that wires
// internal/infrastructure/postgres and the internal/domain/{risk,priority}
// engines into an internal/application.Service for internal/cli to use.
// internal/cli itself only depends on internal/application (AGENTS.md
// §25 Layering).
package main

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/ac1965/riskforge/internal/api"
	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/cli"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/risk"
	"github.com/ac1965/riskforge/internal/infrastructure/datasource/nvd"
	"github.com/ac1965/riskforge/internal/infrastructure/postgres"
	"github.com/ac1965/riskforge/internal/infrastructure/scanner/pownforge"
)

const databaseURLEnv = "RISKFORGE_DATABASE_URL"

// nvdLookupEnabledEnv opts into MatchRawFinding calling out to the real
// NVD CVE API for a CVE it doesn't have a local Vulnerability record for
// yet (ADR 0024). Off by default: this makes outbound network calls
// during `scanner import-pownforge`/HTTP import, which an operator should
// choose explicitly rather than have happen silently.
const nvdLookupEnabledEnv = "RISKFORGE_NVD_LOOKUP_ENABLED"

// nvdAPIKeyEnv is optional -- NVD allows unauthenticated access at a
// lower rate limit; setting this raises it (see nvd.Client).
const nvdAPIKeyEnv = "RISKFORGE_NVD_API_KEY"

func main() {
	if err := cli.NewRootCommand(newService, migrate, api.NewMux, pownforge.Normalize, pownforge.Fetch, pownforge.ExtractEvidence).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func openDB() (*sql.DB, error) {
	dsn := os.Getenv(databaseURLEnv)
	if dsn == "" {
		return nil, fmt.Errorf("%s is not set", databaseURLEnv)
	}
	return postgres.Open(dsn)
}

// migrate applies pending database migrations, for the `riskforge
// migrate` command.
func migrate() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()
	return postgres.Migrate(db)
}

// newService is the application.ServiceFactory every other command uses:
// it connects to PostgreSQL and wires every repository plus the Risk and
// Priority engines. The engines use the default, aggregate-derived
// providers (AGENTS.md §8, §12) with no live threat-intel or CMDB feed
// behind them yet — real Provider implementations are Infrastructure work
// for a later phase.
func newService() (*application.Service, func() error, error) {
	db, err := openDB()
	if err != nil {
		return nil, nil, err
	}

	riskEngine, err := risk.NewEngine(
		risk.FromVulnerabilityProvider{},
		risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{},
		risk.FromAssetProvider{},
		risk.StaticBusinessImpactProvider{},
		risk.BaselinePolicy{},
	)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	priorityEngine, err := priority.NewEngine(
		risk.FromVulnerabilityProvider{},
		risk.FromAssetProvider{},
		risk.FromAssetProvider{},
		priority.FromVulnerabilityRemediationProvider{},
		priority.StaticBusinessConstraintsProvider{},
		priority.BaselinePolicy{},
		priority.NewDefaultSLAPolicy(),
	)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	svc, err := application.NewService(application.Service{
		Assets:              postgres.NewAssetRepository(db),
		Software:            postgres.NewSoftwareRepository(db),
		Vulnerabilities:     postgres.NewVulnerabilityRepository(db),
		RawFindings:         postgres.NewRawFindingRepository(db),
		Findings:            postgres.NewFindingRepository(db),
		RiskAssessments:     postgres.NewRiskAssessmentRepository(db),
		PriorityDecisions:   postgres.NewPriorityDecisionRepository(db),
		RemediationPlans:    postgres.NewRemediationPlanRepository(db),
		Verifications:       postgres.NewVerificationRepository(db),
		Evidence:            postgres.NewEvidenceRepository(db),
		Exceptions:          postgres.NewExceptionRepository(db),
		Audit:               postgres.NewAuditRepository(db),
		Principals:          postgres.NewPrincipalRepository(db),
		APITokens:           postgres.NewAPITokenRepository(db),
		RiskEngine:          riskEngine,
		PriorityEngine:      priorityEngine,
		VulnerabilityLookup: newVulnerabilityLookup(),
	})
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	return svc, db.Close, nil
}

// newVulnerabilityLookup returns an NVD-backed application.VulnerabilityLookup
// (ADR 0024) when nvdLookupEnabledEnv is set, or nil (disabled, the
// pre-ADR-0024 default) otherwise.
func newVulnerabilityLookup() application.VulnerabilityLookup {
	if os.Getenv(nvdLookupEnabledEnv) == "" {
		return nil
	}
	return nvd.NewClient(os.Getenv(nvdAPIKeyEnv))
}
