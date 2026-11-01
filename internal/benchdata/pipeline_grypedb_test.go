//go:build integration && grypedb

package benchdata

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
)

// TestRealPipeline : de bout en bout avec la vraie base Grype, ingestion puis analyse.
// log4j-core 2.14.1 donne CVE-2021-44228 marquée KEV ; l'hôte Debian 12 d'exemple donne
// ses constats dpkg, rattachés à leurs composants (distribution et paquets sources
// arrivés intacts jusqu'à Grype, purl canoniques des deux côtés).
func TestRealPipeline(t *testing.T) {
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
	repoAgent, hostAgent, repo, host, repoRef, hostRef := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
			_, err := tx.ExecContext(ctx, q, args...)
			return err
		}); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}
	exec(`WITH o AS (INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, 'reel', 'Réel', 'fr') RETURNING id) INSERT INTO teams (org_id, id, name) SELECT id, id, 'Général' FROM o`, org)
	exec(`INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', 'depot'), ($1, $3, 'host', 'srv')`, org, repoAgent, hostAgent)
	exec(`INSERT INTO projects (org_id, id, kind, slug, name, agent_id, team_id) VALUES ($1, $2, 'repo', 'rapports', 'Rapports', $3, $1),
		($1, $4, 'host', 'srv', 'srv', $5, $1)`, org, repo, repoAgent, host, hostAgent)
	exec(`INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main'),
		($1, $4, $5, 'host', 'host', 'srv')`, org, repoRef, repo, hostRef, host)
	engine := openReal(t, d.App)
	analyzer := finding.NewAnalyzer(finding.Options{Pool: d.App, Engine: engine, Blobs: ing})
	push := func(agent uuid.UUID, c ingest.Context, file string, ref uuid.UUID) {
		t.Helper()
		body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sbom", file))
		if err != nil {
			t.Fatal(err)
		}
		in, err := ing.Receive(ctx, org, agent, c, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if err := ing.Decode(ctx, org, in.ID); err != nil {
			t.Fatal(err)
		}
		if out, err := analyzer.Analyze(ctx, org, ref); err != nil || out != finding.OutcomeAnalyzed {
			t.Fatalf("%s : %s, %v", file, out, err)
		}
	}
	now := time.Now().Add(-time.Minute)
	push(repoAgent, ingest.Context{ProjectID: repo, RefKind: project.RefBranch, RefName: "main", Commit: "0123456789abcdef0123456789abcdef01234567",
		ScannedAt: now}, "log4shell.cdx16.json", repoRef)
	push(hostAgent, ingest.Context{ProjectID: host, RefKind: project.RefHost, RefName: "srv", ScannedAt: now}, "debian-12.cdx15.json", hostRef)

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error { return tx.QueryRowContext(ctx, q, args...).Scan(&n) }, db.ReadOnly()); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM findings f JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
		WHERE f.vuln_id = 'CVE-2021-44228' AND f.kev AND f.severity = 'critical' AND c.name = 'log4j-core'`); n != 1 {
		t.Fatalf("CVE-2021-44228 KEV : %d constats", n)
	}
	for _, pkg := range []string{"openssl", "libssl3"} {
		if n := count(`SELECT count(*) FROM findings f JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
			WHERE f.ref_id = $1 AND f.vuln_id = 'CVE-2024-5535' AND c.name = $2 AND c.purl LIKE 'pkg:deb/debian/%'`, hostRef, pkg); n != 1 {
			t.Errorf("CVE-2024-5535 sur %s : %d constats", pkg, n)
		}
	}
	for _, pkg := range []string{"curl", "libcurl4", "libc6", "tar", "openssl", "libssl3"} {
		if n := count(`SELECT count(*) FROM findings f JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
			WHERE f.ref_id = $1 AND c.name = $2`, hostRef, pkg); n == 0 {
			t.Errorf("aucun constat pour %s", pkg)
		}
	}
	// Toutes les correspondances sont rattachées à un composant de l'inventaire.
	if n := count(`SELECT unmatched_count FROM ref_analyses WHERE ref_id = $1`, hostRef); n != 0 {
		t.Errorf("%d correspondances de l'hôte sans composant", n)
	}
	t.Logf("hôte Debian 12 : %d constats ouverts", count(`SELECT count(*) FROM findings WHERE ref_id = $1`, hostRef))
}
