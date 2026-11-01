//go:build integration

package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
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
	"leblanc.io/lotor/internal/vuln/vulntest"
)

// Composants du petit jeu connu.
const (
	log4jVuln  = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	log4jOld   = "pkg:maven/org.apache.logging.log4j/log4j-core@2.11.2"
	log4jFixed = "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
	log4jAPI   = "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"
	lodash20   = "pkg:npm/lodash@4.17.20"
	lodash9    = "pkg:npm/lodash@4.9.0"
	lodash15   = "pkg:npm/lodash@4.17.15"
	lodashTag  = "pkg:npm/lodash@latest"
	jqueryHash = "sha256:0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a"
)

// fixture : deux organisations et un petit parc connu, analysé avec une fausse base.
//
// Organisation A :
//   - portail (dépôt, env=prod, exposé-internet) : main = SBOM portail-client-ia
//     (lodash 4.17.21, jquery 3.4.1 trouvé par l'IA avec une empreinte…) ; release/2.3 =
//     lodash 4.17.20, log4j-core 2.17.1 ;
//   - rapports (dépôt, env=dev) : main = log4j-core 2.14.1, log4j-api, lodash 4.9.0 ;
//   - srv-db-02 (serveur, env=prod) : log4j-core 2.11.2, lodash « latest » ;
//   - ancien (dépôt archivé) : log4j-core 2.14.1, lodash 4.17.15 ;
//   - une référence retirée de rapports (old) : log4j-core 2.14.1.
//
// Organisation B : b (dépôt) avec log4j-core 2.14.1 et lodash 4.17.20.
type fixture struct {
	t        *testing.T
	pool     *db.Pool
	search   *Service
	ingest   *ingest.Service
	analyzer *finding.Analyzer
	a, b     tenant.OrgID
	projects map[string]uuid.UUID
	scans    int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	validator, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	ing, err := ingest.NewService(ingest.Options{Pool: d.App, Validator: validator, Logger: slog.New(slog.DiscardHandler),
		Limits: ingest.Limits{MaxUpload: 8 << 20, SBOM: sbom.Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxComponents: 20_000}}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, pool: d.App, search: NewService(d.App, cmp), ingest: ing, projects: map[string]uuid.UUID{}}
	source, engine, dir := &vulntest.Source{}, &vulntest.Engine{}, t.TempDir()
	checker := vuln.NewChecker(vuln.CheckerOptions{Pool: d.App, Source: source, Engine: engine, Dir: dir, MaxArchive: 1 << 20})
	manager := vuln.NewManager(vuln.ManagerOptions{Pool: d.App, Engine: engine, Dir: dir})
	f.analyzer = finding.NewAnalyzer(finding.Options{Pool: d.App, Engine: manager, Blobs: ing})
	log4shell := vuln.Vulnerability{ID: "CVE-2021-44228", Namespace: "nvd:cpe", Severity: vuln.SeverityCritical,
		KEV: &vuln.KEV{Ransomware: true}, Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Risk: 99}
	lodashVuln := vuln.Vulnerability{ID: "CVE-2021-23337", Namespace: "nvd:cpe", Severity: vuln.SeverityHigh, Risk: 60}
	built := time.Date(2026, 10, 30, 6, 0, 0, 0, time.UTC)
	source.Publish(vulntest.Archive(t, vulntest.Content{Built: built, Rules: []vulntest.Rule{
		{PURL: log4jVuln, Vuln: log4shell, Match: vuln.Match{FixedVersions: []string{"2.15.0", "2.12.2"}, FixState: vuln.FixFixed, Risk: 99}},
		{PURL: log4jOld, Vuln: log4shell, Match: vuln.Match{FixedVersions: []string{"2.12.2"}, FixState: vuln.FixFixed, Risk: 97}},
		{PURL: lodash20, Vuln: lodashVuln, Match: vuln.Match{FixedVersions: []string{"4.17.21"}, FixState: vuln.FixFixed, Risk: 60}},
		{PURL: lodash9, Vuln: lodashVuln, Match: vuln.Match{FixedVersions: []string{"4.17.21"}, FixState: vuln.FixFixed, Risk: 61}},
	}}), built, "")
	if _, err := checker.Check(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.a, f.b = f.newOrg("atelier"), f.newOrg("autre")
	repoA, hostA := f.agent(f.a, "repo", "depots"), f.agent(f.a, "host", "srv-db-02")
	portail := f.project(f.a, "repo", "portail", `{"env": "prod", "exposé-internet": ""}`, repoA)
	f.push(f.a, repoA, portail, "main", testdata(t, "portail-client-ia.cdx16.json"))
	f.push(f.a, repoA, portail, "release/2.3", cdx(lodash20, log4jFixed))
	rapports := f.project(f.a, "repo", "rapports", `{"env": "dev"}`, repoA)
	f.push(f.a, repoA, rapports, "main", cdx(log4jVuln, log4jAPI, lodash9))
	f.push(f.a, repoA, rapports, "old", cdx(log4jVuln))
	f.exec(f.a, `UPDATE tracked_refs SET removed_at = now() WHERE project_id = $1 AND name = 'old'`, rapports)
	host := f.project(f.a, "host", "srv-db-02", `{"env": "prod"}`, hostA)
	f.push(f.a, hostA, host, "srv-db-02", cdx(log4jOld, lodashTag))
	ancien := f.project(f.a, "repo", "ancien", `{}`, repoA)
	f.push(f.a, repoA, ancien, "main", cdx(log4jVuln, lodash15))
	f.exec(f.a, `UPDATE projects SET archived_at = now() WHERE id = $1`, ancien)
	repoB := f.agent(f.b, "repo", "depots")
	other := f.project(f.b, "repo", "b", `{"env": "prod"}`, repoB)
	f.push(f.b, repoB, other, "main", cdx(log4jVuln, lodash20))
	return f
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cdx écrit un SBOM CycloneDX 1.6 minimal des purl donnés.
func cdx(purls ...string) []byte {
	type comp struct {
		BOMRef  string `json:"bom-ref"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	}
	var cs []comp
	for _, p := range purls {
		at := strings.LastIndexByte(p, '@')
		name := p[strings.LastIndexByte(p[:at], '/')+1 : at]
		cs = append(cs, comp{BOMRef: p, Type: "library", Name: name, Version: p[at+1:], PURL: p})
	}
	b, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata":   map[string]any{"component": map[string]any{"bom-ref": "app", "type": "application", "name": "app"}},
		"components": cs})
	return b
}

func (f *fixture) exec(org tenant.OrgID, query string, args ...any) {
	f.t.Helper()
	if err := f.pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s : %v", query, err)
	}
}

func (f *fixture) newOrg(slug string) tenant.OrgID {
	org, err := tenant.NewOrgID()
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(org, `WITH o AS (INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, $2, 'fr') RETURNING id) INSERT INTO teams (org_id, id, name) SELECT id, id, 'Général' FROM o`, org, slug)
	return org
}

func (f *fixture) agent(org tenant.OrgID, kind, name string) uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	f.exec(org, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, $3, $4)`, org, id, kind, name)
	return id
}

func (f *fixture) project(org tenant.OrgID, kind, slug, labels string, agent uuid.UUID) uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	f.exec(org, `INSERT INTO projects (org_id, id, kind, slug, name, labels, agent_id, team_id) VALUES ($1, $2, $3, $4, $4, $5, $6, $1)`,
		org, id, kind, slug, labels, agent)
	if kind == "host" {
		f.exec(org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'host', 'host', $4)`,
			org, uuid.Must(uuid.NewV7()), id, slug)
	}
	f.projects[slug] = id
	return id
}

// push envoie data sur la référence ref (créée au besoin) et l'analyse.
func (f *fixture) push(org tenant.OrgID, agent, projectID uuid.UUID, ref string, data []byte) {
	f.t.Helper()
	ctx := context.Background()
	f.scans++
	c := ingest.Context{ProjectID: projectID, RefKind: project.RefBranch, RefName: ref, Commit: fmt.Sprintf("%040x", f.scans),
		AgentVersion: "1.0.0", ScannedAt: time.Now().Add(-time.Hour + time.Duration(f.scans)*time.Second)}
	var kind string
	if err := f.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT kind FROM projects WHERE id = $1`, projectID).Scan(&kind)
	}); err != nil {
		f.t.Fatal(err)
	}
	if kind == "host" {
		c.RefKind, c.Commit = project.RefHost, ""
	} else {
		f.exec(org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', $4)
			ON CONFLICT DO NOTHING`, org, uuid.Must(uuid.NewV7()), projectID, ref)
	}
	in, err := f.ingest.Receive(ctx, org, agent, c, bytes.NewReader(data))
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.ingest.Decode(ctx, org, in.ID); err != nil {
		f.t.Fatal(err)
	}
	var refID uuid.UUID
	if err := f.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT ref_id FROM ingestions WHERE id = $1 AND status = 'done'`, in.ID).Scan(&refID)
	}); err != nil {
		f.t.Fatalf("ingestion %s : %v", ref, err)
	}
	if _, err := f.analyzer.Analyze(ctx, org, refID); err != nil {
		f.t.Fatal(err)
	}
}

// run cherche q (paramètres d'URL) dans org.
func (f *fixture) run(org tenant.OrgID, params string) Result {
	f.t.Helper()
	req := f.request(params)
	res, err := f.search.Search(context.Background(), org, tenant.AllTeams(), req)
	if err != nil {
		f.t.Fatalf("%s : %v", params, err)
	}
	return res
}

func (f *fixture) request(params string) Request {
	f.t.Helper()
	v, err := url.ParseQuery(params)
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := ParseRequest(v)
	if err != nil {
		f.t.Fatalf("%s : %v", params, err)
	}
	return req
}

// agentOf renvoie l'agent nommé name de org.
func (f *fixture) agentOf(org tenant.OrgID, name string) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT id FROM agents WHERE name = $1`, name).Scan(&id)
	}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// occurrences liste les occurrences d'un résultat, « projet/référence:purl ».
func occurrences(res Result) []string {
	var out []string
	for _, g := range res.Groups {
		for _, h := range g.Hits {
			out = append(out, g.Project.Slug+"/"+h.RefName+":"+h.PURL)
		}
	}
	return out
}
