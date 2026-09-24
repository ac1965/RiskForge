//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/ac1965/riskforge/internal/domain/asset"
	"github.com/ac1965/riskforge/internal/domain/audit"
	"github.com/ac1965/riskforge/internal/domain/evidence"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/explainability"
	"github.com/ac1965/riskforge/internal/domain/finding"
	"github.com/ac1965/riskforge/internal/domain/priority"
	"github.com/ac1965/riskforge/internal/domain/remediation"
	"github.com/ac1965/riskforge/internal/domain/risk"
	"github.com/ac1965/riskforge/internal/domain/software"
	"github.com/ac1965/riskforge/internal/domain/verification"
	"github.com/ac1965/riskforge/internal/domain/vulnerability"
)

// setupDB starts a throwaway PostgreSQL container (AGENTS.md §25A.6:
// integration tests involving PostgreSQL use testcontainers-go), applies
// every migration, and returns a connected *sql.DB.
func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("riskforge_test"),
		tcpostgres.WithUsername("riskforge"),
		tcpostgres.WithPassword("riskforge"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	db, err := Open(dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	return db
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := setupDB(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate() call unexpected error: %v", err)
	}
}

func TestAssetRepository(t *testing.T) {
	db := setupDB(t)
	repo := NewAssetRepository(db)
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := asset.New(asset.Params{
		Hostname:       "web-01",
		FQDN:           "web-01.internal.example.com",
		IPAddresses:    []string{"10.0.0.5"},
		MACAddresses:   []string{"aa:bb:cc:dd:ee:ff"},
		Type:           asset.TypeServer,
		Environment:    asset.EnvironmentProduction,
		Criticality:    asset.CriticalityHigh,
		Exposure:       asset.Exposure{Level: asset.LevelDirect, InternetExposed: true},
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: asset.LifecycleActive,
	})
	if err != nil {
		t.Fatalf("asset.New() unexpected error: %v", err)
	}

	if err := repo.Save(ctx, a); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	found, err := repo.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if found == nil {
		t.Fatal("FindByID() = nil, want the saved asset")
	}
	if found.Hostname != a.Hostname || len(found.IPAddresses) != 1 || found.IPAddresses[0] != "10.0.0.5" {
		t.Errorf("FindByID() = %+v, want round-tripped %+v", found, a)
	}
	if !found.Exposure.InternetExposed || found.Exposure.Level != asset.LevelDirect {
		t.Errorf("FindByID() exposure = %+v, want round-tripped %+v", found.Exposure, a.Exposure)
	}

	byHostname, err := repo.FindByHostname(ctx, "web-01")
	if err != nil {
		t.Fatalf("FindByHostname() unexpected error: %v", err)
	}
	if byHostname == nil || byHostname.ID != a.ID {
		t.Errorf("FindByHostname() = %+v, want asset %s", byHostname, a.ID)
	}

	missing, err := repo.FindByHostname(ctx, "does-not-exist")
	if err != nil {
		t.Fatalf("FindByHostname() unexpected error: %v", err)
	}
	if missing != nil {
		t.Errorf("FindByHostname() for unknown host = %+v, want nil", missing)
	}

	// Save again with an updated LastSeen: same id, must update in place
	// (upsert), not create a second row.
	if err := a.Observe(now.Add(24 * time.Hour)); err != nil {
		t.Fatalf("Observe() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, a); err != nil {
		t.Fatalf("second Save() unexpected error: %v", err)
	}
	updated, err := repo.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if !updated.LastSeen.Equal(now.Add(24 * time.Hour)) {
		t.Errorf("LastSeen = %s, want advanced timestamp", updated.LastSeen)
	}
}

func mustAsset(t *testing.T) *asset.Asset {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := asset.New(asset.Params{
		Hostname:       "host-01",
		Type:           asset.TypeServer,
		Environment:    asset.EnvironmentProduction,
		Criticality:    asset.CriticalityHigh,
		Exposure:       asset.Exposure{Level: asset.LevelInternalOnly},
		FirstSeen:      now,
		LastSeen:       now,
		LifecycleState: asset.LifecycleActive,
	})
	if err != nil {
		t.Fatalf("asset.New() unexpected error: %v", err)
	}
	return a
}

func mustVulnerability(t *testing.T) *vulnerability.Vulnerability {
	t.Helper()
	score := 9.8
	v, err := vulnerability.New(vulnerability.Params{
		CVEID:       "CVE-2026-00001",
		Title:       "Test vulnerability",
		Severity:    vulnerability.SeverityCritical,
		CVSSv3:      &score,
		CWE:         []string{"CWE-79"},
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Provenance: vulnerability.Provenance{
			Source:      "NVD",
			SourceID:    "CVE-2026-00001",
			RetrievedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("vulnerability.New() unexpected error: %v", err)
	}
	return v
}

func TestSoftwareRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}

	repo := NewSoftwareRepository(db)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inst, err := software.New(software.Params{
		AssetID:   a.ID,
		Vendor:    "openssl",
		Product:   "openssl",
		Version:   "3.0.13",
		CPE:       "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		FirstSeen: now,
		LastSeen:  now,
	})
	if err != nil {
		t.Fatalf("software.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, inst); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	found, err := repo.FindByNaturalKey(ctx, a.ID, "openssl", "openssl", "3.0.13")
	if err != nil {
		t.Fatalf("FindByNaturalKey() unexpected error: %v", err)
	}
	if found == nil || found.ID != inst.ID {
		t.Errorf("FindByNaturalKey() = %+v, want installation %s", found, inst.ID)
	}

	missing, err := repo.FindByNaturalKey(ctx, a.ID, "openssl", "openssl", "9.9.9")
	if err != nil {
		t.Fatalf("FindByNaturalKey() unexpected error: %v", err)
	}
	if missing != nil {
		t.Errorf("FindByNaturalKey() for unknown version = %+v, want nil", missing)
	}
}

func TestVulnerabilityRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()
	repo := NewVulnerabilityRepository(db)

	v := mustVulnerability(t)
	if err := repo.Save(ctx, v); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	found, err := repo.FindByID(ctx, v.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if found == nil {
		t.Fatal("FindByID() = nil, want the saved vulnerability")
	}
	if found.CVEID != v.CVEID || found.CVSSv3 == nil || *found.CVSSv3 != *v.CVSSv3 {
		t.Errorf("FindByID() = %+v, want round-tripped %+v", found, v)
	}
	if len(found.CWE) != 1 || found.CWE[0] != "CWE-79" {
		t.Errorf("FindByID() CWE = %v, want [CWE-79]", found.CWE)
	}
	if found.Provenance.Source != "NVD" || found.Provenance.RetrievedAt.IsZero() {
		t.Errorf("FindByID() Provenance = %+v, want round-tripped %+v", found.Provenance, v.Provenance)
	}
}

func mustFinding(t *testing.T, db *sql.DB, a *asset.Asset, v *vulnerability.Vulnerability) *finding.Finding {
	t.Helper()
	ctx := context.Background()

	f, err := finding.New(finding.Params{
		AssetID:         a.ID,
		VulnerabilityID: v.ID,
		DetectionSource: "test-scanner",
		DetectedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Confidence:      finding.ConfidenceConfirmed,
	})
	if err != nil {
		t.Fatalf("finding.New() unexpected error: %v", err)
	}
	if err := NewFindingRepository(db).Save(ctx, f); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	return f
}

func TestFindingRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	v := mustVulnerability(t)
	if err := NewVulnerabilityRepository(db).Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}

	repo := NewFindingRepository(db)
	f := mustFinding(t, db, a, v)

	found, err := repo.FindByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if found == nil || found.Status != finding.StatusOpen {
		t.Errorf("FindByID() = %+v, want status %s", found, finding.StatusOpen)
	}

	byPair, err := repo.FindByAssetAndVulnerability(ctx, a.ID, v.ID)
	if err != nil {
		t.Fatalf("FindByAssetAndVulnerability() unexpected error: %v", err)
	}
	if byPair == nil || byPair.ID != f.ID {
		t.Errorf("FindByAssetAndVulnerability() = %+v, want finding %s", byPair, f.ID)
	}

	// Round-trip a status transition through the domain state machine and
	// re-save, to catch a CHECK constraint mismatch with finding.Status.
	if err := found.TransitionTo(finding.StatusMitigated); err != nil {
		t.Fatalf("TransitionTo() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, found); err != nil {
		t.Fatalf("Save() after transition unexpected error: %v", err)
	}
	reloaded, err := repo.FindByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if reloaded.Status != finding.StatusMitigated {
		t.Errorf("Status = %s, want %s", reloaded.Status, finding.StatusMitigated)
	}
}

func TestRiskAssessmentRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	v := mustVulnerability(t)
	if err := NewVulnerabilityRepository(db).Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}
	f := mustFinding(t, db, a, v)

	repo := NewRiskAssessmentRepository(db)

	older, err := risk.New(risk.Params{
		FindingID:     f.ID,
		Score:         40,
		Level:         risk.LevelMedium,
		Factors:       []explainability.Factor{{Name: "severity", Value: "medium", Reason: "test"}},
		PolicyName:    "baseline",
		PolicyVersion: "1.0.0",
		AssessedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("risk.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, older); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	newer, err := risk.New(risk.Params{
		FindingID:     f.ID,
		Score:         90,
		Level:         risk.LevelCritical,
		Factors:       []explainability.Factor{{Name: "kev_listed", Value: "true", Reason: "CISA KEV"}},
		PolicyName:    "baseline",
		PolicyVersion: "1.0.0",
		AssessedAt:    time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("risk.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, newer); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	latest, err := repo.FindLatestByFinding(ctx, f.ID)
	if err != nil {
		t.Fatalf("FindLatestByFinding() unexpected error: %v", err)
	}
	if latest == nil || latest.ID != newer.ID {
		t.Errorf("FindLatestByFinding() = %+v, want the newer assessment %s", latest, newer.ID)
	}
	if len(latest.Factors) != 1 || latest.Factors[0].Name != "kev_listed" {
		t.Errorf("FindLatestByFinding() Factors = %+v, want round-tripped kev_listed factor", latest.Factors)
	}
}

func TestPriorityDecisionRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	v := mustVulnerability(t)
	if err := NewVulnerabilityRepository(db).Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}
	f := mustFinding(t, db, a, v)

	ra, err := risk.New(risk.Params{
		FindingID:  f.ID,
		Score:      50,
		Level:      risk.LevelMedium,
		Factors:    []explainability.Factor{{Name: "severity", Value: "medium", Reason: "test"}},
		PolicyName: "baseline",
		AssessedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("risk.New() unexpected error: %v", err)
	}
	if err := NewRiskAssessmentRepository(db).Save(ctx, ra); err != nil {
		t.Fatalf("save risk assessment: %v", err)
	}

	repo := NewPriorityDecisionRepository(db)
	d, err := priority.New(priority.Params{
		FindingID:        f.ID,
		RiskAssessmentID: ra.ID,
		Rank:             65,
		Level:            priority.LevelHigh,
		Factors:          []explainability.Factor{{Name: "asset_criticality", Value: "high", Reason: "test"}},
		SLADeadline:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		PolicyName:       "baseline",
		DecidedAt:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("priority.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, d); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	latest, err := repo.FindLatestByFinding(ctx, f.ID)
	if err != nil {
		t.Fatalf("FindLatestByFinding() unexpected error: %v", err)
	}
	if latest == nil || latest.ID != d.ID {
		t.Errorf("FindLatestByFinding() = %+v, want decision %s", latest, d.ID)
	}
	if !latest.SLADeadline.Equal(d.SLADeadline) {
		t.Errorf("SLADeadline = %s, want %s", latest.SLADeadline, d.SLADeadline)
	}
}

func TestRemediationPlanRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	v := mustVulnerability(t)
	if err := NewVulnerabilityRepository(db).Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}
	f := mustFinding(t, db, a, v)

	repo := NewRemediationPlanRepository(db)
	plan, err := remediation.New(remediation.Params{
		FindingID:   f.ID,
		ActionType:  remediation.ActionPatch,
		Description: "Apply vendor patch",
		ProposedBy:  "alice",
		Rollback:    remediation.Rollback{Capable: true, Plan: "Downgrade package"},
	})
	if err != nil {
		t.Fatalf("remediation.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, plan); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	if err := plan.Approve("bob"); err != nil {
		t.Fatalf("Approve() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, plan); err != nil {
		t.Fatalf("Save() after approve unexpected error: %v", err)
	}

	found, err := repo.FindByID(ctx, plan.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if found == nil || found.Status != remediation.StatusApproved || found.ApprovedBy != "bob" {
		t.Errorf("FindByID() = %+v, want approved by bob", found)
	}
	if !found.Rollback.Capable || found.Rollback.Plan != "Downgrade package" {
		t.Errorf("FindByID() Rollback = %+v, want round-tripped rollback plan", found.Rollback)
	}
}

func TestEvidenceRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	v := mustVulnerability(t)
	if err := NewVulnerabilityRepository(db).Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}
	f := mustFinding(t, db, a, v)

	repo := NewEvidenceRepository(db)
	content := []byte("scan output")
	ev, err := evidence.New(evidence.Params{
		Type:        evidence.TypeDetectionResult,
		Source:      "nessus",
		CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		AssetID:     a.ID,
		FindingID:   f.ID,
		ContentHash: evidence.ComputeContentHash(content),
		Location:    "s3://evidence/scan-1.json",
	})
	if err != nil {
		t.Fatalf("evidence.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, ev); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}
	// Saving the exact same Evidence again must be a harmless no-op, not
	// an error (immutability, AGENTS.md §17, §22, §47.10).
	if err := repo.Save(ctx, ev); err != nil {
		t.Fatalf("second Save() unexpected error: %v", err)
	}

	found, err := repo.FindByID(ctx, ev.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if found == nil || found.FindingID != f.ID || found.ContentHash != ev.ContentHash {
		t.Errorf("FindByID() = %+v, want round-tripped %+v", found, ev)
	}

	// FindingID is optional (AGENTS.md §17).
	noFinding, err := evidence.New(evidence.Params{
		Type:        evidence.TypePackageInfo,
		Source:      "riskforge-agent",
		CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		AssetID:     a.ID,
		ContentHash: evidence.ComputeContentHash([]byte("pkg list")),
		Location:    "s3://evidence/pkglist.json",
	})
	if err != nil {
		t.Fatalf("evidence.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, noFinding); err != nil {
		t.Fatalf("Save() with no finding id unexpected error: %v", err)
	}
	foundNoFinding, err := repo.FindByID(ctx, noFinding.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if foundNoFinding.FindingID != "" {
		t.Errorf("FindingID = %q, want empty", foundNoFinding.FindingID)
	}
}

func TestVerificationRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	v := mustVulnerability(t)
	if err := NewVulnerabilityRepository(db).Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}
	f := mustFinding(t, db, a, v)

	ev, err := evidence.New(evidence.Params{
		Type:        evidence.TypeVerificationResult,
		Source:      "riskforge-agent",
		CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		AssetID:     a.ID,
		FindingID:   f.ID,
		ContentHash: evidence.ComputeContentHash([]byte("version check output")),
		Location:    "s3://evidence/verify-1.json",
	})
	if err != nil {
		t.Fatalf("evidence.New() unexpected error: %v", err)
	}
	if err := NewEvidenceRepository(db).Save(ctx, ev); err != nil {
		t.Fatalf("save evidence: %v", err)
	}

	repo := NewVerificationRepository(db)
	ver, err := verification.New(verification.Params{
		FindingID:  f.ID,
		Method:     verification.MethodVersionCheck,
		VerifiedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		Result:     verification.ResultPass,
		EvidenceID: ev.ID,
	})
	if err != nil {
		t.Fatalf("verification.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, ver); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}
}

func TestExceptionRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	a := mustAsset(t)
	if err := NewAssetRepository(db).Save(ctx, a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	v := mustVulnerability(t)
	if err := NewVulnerabilityRepository(db).Save(ctx, v); err != nil {
		t.Fatalf("save vulnerability: %v", err)
	}
	f := mustFinding(t, db, a, v)

	repo := NewExceptionRepository(db)
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e, err := exception.New(exception.Params{
		FindingID:   f.ID,
		Reason:      "Confirmed false positive",
		RequestedBy: "alice",
		CreatedAt:   created,
		ExpiresAt:   created.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("exception.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, e); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	if err := e.Approve("bob"); err != nil {
		t.Fatalf("Approve() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, e); err != nil {
		t.Fatalf("Save() after approve unexpected error: %v", err)
	}

	found, err := repo.FindByID(ctx, e.ID)
	if err != nil {
		t.Fatalf("FindByID() unexpected error: %v", err)
	}
	if found == nil || found.Status != exception.StatusApproved || found.ApprovedBy != "bob" {
		t.Errorf("FindByID() = %+v, want approved by bob", found)
	}
}

func TestAuditRepository(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	repo := NewAuditRepository(db)
	e, err := audit.New(audit.Params{
		Action:      audit.ActionRiskChange,
		Who:         "system",
		SubjectType: "finding",
		SubjectID:   "finding-123",
		What:        "Assessed risk",
		Why:         "Automated risk assessment via policy \"baseline\" v1.0.0",
		Before:      "",
		After:       `{"score":90}`,
		OccurredAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("audit.New() unexpected error: %v", err)
	}
	if err := repo.Save(ctx, e); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}
}
