//go:build integration && grypedb

package benchdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/grype"
)

// realEngine sert une vraie base Grype ouverte directement (sans synchronisation depuis
// PostgreSQL), déclarée cible sous l'identifiant archive.
type realEngine struct {
	d       vuln.Database
	version vuln.Version
}

func (e *realEngine) Ensure(context.Context) (vuln.Version, error) { return e.version, nil }

func (e *realEngine) Match(ctx context.Context, blob []byte) (vuln.Result, error) {
	ms, vs, err := e.d.Match(ctx, blob)
	return vuln.Result{Version: e.version, Matches: ms, Vulnerabilities: vs}, err
}

// openReal ouvre la base de LOTOR_TEST_GRYPEDB_DIR et la déclare cible dans la base de
// test (archive fictive : seule la cible compte pour l'analyse).
func openReal(t *testing.T, pool *db.Pool) *realEngine {
	t.Helper()
	dir := os.Getenv("LOTOR_TEST_GRYPEDB_DIR")
	if dir == "" {
		t.Fatal("LOTOR_TEST_GRYPEDB_DIR : répertoire d'une base Grype v6 installée")
	}
	start := time.Now()
	d, err := grype.NewEngine().Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ouverture de la base : %s", time.Since(start).Round(time.Millisecond))
	t.Cleanup(func() { _ = d.Close() })
	e := &realEngine{d: d, version: vuln.Version{ArchiveID: uuid.Must(uuid.NewV7()), Built: d.Description().Built.Round(time.Microsecond),
		Schema: d.Description().Schema}}
	sum := sha256.Sum256(e.version.ArchiveID[:])
	if err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO vulndb_archives (id, sha256, size, chunk_count, schema, built_at, origin, created_at)
			VALUES ($1, $2, 1, 1, $3, $4, 'import', now())`, e.version.ArchiveID, sum[:], e.version.Schema, e.version.Built); err != nil {
			return err
		}
		_, err := tx.ExecContext(context.Background(), `UPDATE vulndb_state SET target_archive_id = $1, target_set_at = now()`, e.version.ArchiveID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestIngestAndAnalyze5000 mesure l'ingestion et l'analyse d'un SBOM de 5 000 composants
// (critère de T06 : moins de 30 s au 95e centile), selon docs/benchmarks.md : réception,
// décodage et rangement, analyse Grype et écriture des constats, de bout en bout.
func TestIngestAndAnalyze5000(t *testing.T) {
	ctx := context.Background()
	d := dbtest.New(t)
	validator, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	ing, err := ingest.NewService(ingest.Options{Pool: d.App, Validator: validator, Logger: slog.New(slog.DiscardHandler),
		Limits: ingest.Limits{MaxUpload: 32 << 20, SBOM: sbom.Limits{MaxBytes: 64 << 20, MaxDepth: 64, MaxComponents: 50_000}}})
	if err != nil {
		t.Fatal(err)
	}
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	agentID, repo, ref := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, 'bench', 'Bench', 'fr')`, []any{org}},
			{`INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', 'agent')`, []any{org, agentID}},
			{`INSERT INTO projects (org_id, id, kind, slug, name, agent_id) VALUES ($1, $2, 'repo', 'bench', 'Bench', $3)`, []any{org, repo, agentID}},
			{`INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main')`, []any{org, ref, repo}},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	engine := openReal(t, d.App)
	analyzer := finding.NewAnalyzer(finding.Options{Pool: d.App, Engine: engine, Blobs: ing})
	run := func(i int) (time.Duration, time.Duration) {
		body, err := SyntheticCycloneDX(5000, i)
		if err != nil {
			t.Fatal(err)
		}
		c := ingest.Context{ProjectID: repo, RefKind: project.RefBranch, RefName: "main", Commit: strings.Repeat("0", 32) + uuidHex(i),
			AgentVersion: "bench", ScannedAt: time.Now().Add(-time.Hour + time.Duration(i)*time.Second)}
		start := time.Now()
		in, err := ing.Receive(ctx, org, agentID, c, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if err := ing.Decode(ctx, org, in.ID); err != nil {
			t.Fatal(err)
		}
		ingested := time.Since(start)
		out, err := analyzer.Analyze(ctx, org, ref)
		if err != nil || out != finding.OutcomeAnalyzed {
			t.Fatalf("analyse %d : %s, %v", i, out, err)
		}
		return ingested, time.Since(start)
	}
	// Premier passage sur la base fraîchement ouverte (cache froid de Grype), puis
	// passages à chaud.
	_, cold := run(0)
	var totals, ingests []time.Duration
	for i := 1; i <= 20; i++ {
		ing, total := run(i)
		totals, ingests = append(totals, total), append(ingests, ing)
	}
	slices.Sort(totals)
	slices.Sort(ingests)
	p95 := totals[len(totals)*95/100]
	var findings int
	if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE status = 'open'`).Scan(&findings)
	}, db.ReadOnly()); err != nil {
		t.Fatal(err)
	}
	t.Logf("5 000 composants, %d constats ouverts : froid %s ; chaud p50 %s, p95 %s, max %s (dont ingestion p95 %s)",
		findings, cold.Round(time.Millisecond), totals[len(totals)/2].Round(time.Millisecond), p95.Round(time.Millisecond),
		totals[len(totals)-1].Round(time.Millisecond), ingests[len(ingests)*95/100].Round(time.Millisecond))
	if findings == 0 {
		t.Error("aucun constat : la base n'a rien reconnu")
	}
	if p95 > 30*time.Second || cold > 30*time.Second {
		t.Errorf("cible de 30 s au 95e centile dépassée : p95 %s, froid %s", p95, cold)
	}
}

func uuidHex(i int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for k := 7; k >= 0; k-- {
		out[k] = hex[i&15]
		i >>= 4
	}
	return string(out)
}
