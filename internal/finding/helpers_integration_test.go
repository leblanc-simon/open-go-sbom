//go:build integration

package finding

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/vulntest"
)

const (
	log4jOld = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	log4jNew = "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
	apiOld   = "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"
)

var built1 = time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)

// env : une base, une base de vulnérabilités factice, un Checker, et une organisation
// avec un dépôt (branche main), confié à un agent dépôt.
type env struct {
	t        *testing.T
	pool     *db.Pool
	ingest   *ingest.Service
	source   *vulntest.Source
	engine   *vulntest.Engine
	checker  *vuln.Checker
	manager  *vuln.Manager
	analyzer *Analyzer
	org      tenant.OrgID
	agent    uuid.UUID
	repo     uuid.UUID
	main     uuid.UUID
	scans    int
}

func newEnv(t *testing.T) *env {
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
	e := &env{t: t, pool: d.App, ingest: ing, source: &vulntest.Source{}, engine: &vulntest.Engine{}}
	dir := t.TempDir()
	e.checker = vuln.NewChecker(vuln.CheckerOptions{Pool: e.pool, Source: e.source, Engine: e.engine, Dir: dir, MaxArchive: 1 << 20})
	e.manager = vuln.NewManager(vuln.ManagerOptions{Pool: e.pool, Engine: e.engine, Dir: dir})
	e.analyzer = NewAnalyzer(Options{Pool: e.pool, Engine: e.manager, Blobs: ing})
	e.org, e.agent, e.repo, e.main = e.newOrg("depot")
	return e
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

// newOrg crée une organisation avec un agent dépôt et un dépôt « slug » (branche main).
func (e *env) newOrg(slug string) (tenant.OrgID, uuid.UUID, uuid.UUID, uuid.UUID) {
	e.t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		e.t.Fatal(err)
	}
	agent, repo, main := newID(), newID(), newID()
	suffix := strings.ReplaceAll(org.String()[24:], "-", "")
	e.execIn(org, `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, 'Org', 'fr')`, org, "o-"+suffix)
	e.execIn(org, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', 'agent')`, org, agent)
	e.execIn(org, `INSERT INTO projects (org_id, id, kind, slug, name, agent_id) VALUES ($1, $2, 'repo', $3, $3, $4)`, org, repo, slug, agent)
	e.execIn(org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main')`,
		org, main, repo)
	return org, agent, repo, main
}

func (e *env) execIn(org tenant.OrgID, query string, args ...any) {
	e.t.Helper()
	if err := e.pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	}); err != nil {
		e.t.Fatalf("%s : %v", query, err)
	}
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	return e.countIn(e.org, query, args...)
}

func (e *env) countIn(org tenant.OrgID, query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), query, args...).Scan(&n)
	}); err != nil {
		e.t.Fatalf("%s : %v", query, err)
	}
	return n
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sbomWith : le SBOM log4shell, log4j-core à la version v.
func sbomWith(t *testing.T, v string) []byte {
	return bytes.ReplaceAll(testdata(t, "log4shell.cdx16.json"), []byte("log4j-core@2.14.1"), []byte("log4j-core@"+v))
}

// ingestIn envoie data sur la branche main du dépôt et le décode, comme le ferait le job.
func (e *env) ingestIn(org tenant.OrgID, agent, repo uuid.UUID, data []byte) {
	e.t.Helper()
	e.scans++
	c := ingest.Context{ProjectID: repo, RefKind: project.RefBranch, RefName: "main", Commit: fmt.Sprintf("%040x", e.scans),
		AgentVersion: "1.0.0", ScannedAt: time.Now().Add(-time.Hour + time.Duration(e.scans)*time.Second)}
	in, err := e.ingest.Receive(context.Background(), org, agent, c, bytes.NewReader(data))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.ingest.Decode(context.Background(), org, in.ID); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) push(data []byte) { e.ingestIn(e.org, e.agent, e.repo, data) }

func log4shellRule() vulntest.Rule {
	return vulntest.Rule{PURL: log4jOld,
		Vuln: vuln.Vulnerability{ID: "CVE-2021-44228", Namespace: "nvd:cpe", Severity: vuln.SeverityCritical,
			KEV: &vuln.KEV{Ransomware: true}, EPSS: &vuln.EPSS{Score: 0.944, Percentile: 0.999},
			CVSS:    []vuln.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", BaseScore: 10}},
			Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Risk: 99},
		Match: vuln.Match{FixedVersions: []string{"2.15.0"}, FixState: vuln.FixFixed, Risk: 99}}
}

func apiRule() vulntest.Rule {
	return vulntest.Rule{PURL: apiOld, Vuln: vuln.Vulnerability{ID: "CVE-2099-0001", Severity: vuln.SeverityLow, Risk: 1}}
}

// publish annonce une base et en fait la cible.
func (e *env) publish(built time.Time, rules ...vulntest.Rule) vuln.Archive {
	e.t.Helper()
	e.source.Publish(vulntest.Archive(e.t, vulntest.Content{Built: built, Rules: rules}), built, "")
	a, err := e.checker.Check(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return *a
}

func (e *env) analyze(org tenant.OrgID, ref uuid.UUID) Outcome {
	e.t.Helper()
	out, err := e.analyzer.Analyze(context.Background(), org, ref)
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

type findingState struct {
	Status     Status
	Resolution string
	Archive    uuid.UUID
	KEV        bool
	Severity   string
	Events     int
}

func (e *env) finding(component, vulnID string) (findingState, bool) {
	e.t.Helper()
	var f findingState
	var res *string
	var found bool
	err := e.pool.InOrg(context.Background(), e.org, func(tx *db.OrgTx) error {
		err := tx.QueryRowContext(context.Background(), `
			SELECT f.status, f.resolution, f.vulndb_archive, f.kev, f.severity,
			       (SELECT count(*) FROM finding_events ev WHERE ev.org_id = f.org_id AND ev.finding_id = f.id)
			  FROM findings f JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
			 WHERE c.purl = $1 AND f.vuln_id = $2`, component, vulnID).
			Scan(&f.Status, &res, &f.Archive, &f.KEV, &f.Severity, &f.Events)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if res != nil {
		f.Resolution = *res
	}
	return f, found
}
