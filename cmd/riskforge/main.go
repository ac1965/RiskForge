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

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/cli"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/risk"
	"github.com/ac1965/riskforge/internal/infrastructure/postgres"
)

const databaseURLEnv = "RISKFORGE_DATABASE_URL"

func main() {
	if err := cli.NewRootCommand(newService, migrate).Execute(); err != nil {
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
		Assets:            postgres.NewAssetRepository(db),
		Software:          postgres.NewSoftwareRepository(db),
		Vulnerabilities:   postgres.NewVulnerabilityRepository(db),
		Findings:          postgres.NewFindingRepository(db),
		RiskAssessments:   postgres.NewRiskAssessmentRepository(db),
		PriorityDecisions: postgres.NewPriorityDecisionRepository(db),
		RemediationPlans:  postgres.NewRemediationPlanRepository(db),
		Verifications:     postgres.NewVerificationRepository(db),
		Evidence:          postgres.NewEvidenceRepository(db),
		Exceptions:        postgres.NewExceptionRepository(db),
		Audit:             postgres.NewAuditRepository(db),
		RiskEngine:        riskEngine,
		PriorityEngine:    priorityEngine,
	})
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	return svc, db.Close, nil
}
