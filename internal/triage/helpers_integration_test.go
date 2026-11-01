//go:build integration

package triage_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/version/grypeversion"
)

const (
	log4jBase = "pkg:maven/org.apache.logging.log4j/log4j-core"
	log4jOld  = log4jBase + "@2.14.1"
	log4jNew  = log4jBase + "@2.17.1"
	cve       = "CVE-2021-44228"
)

// clock est une horloge de test réglable, arrondie à la microseconde (dates relues de
// PostgreSQL).
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t.Round(time.Microsecond)
}

// env : une base, un service de triage à horloge réglable, et les changements reçus par
// OnChange.
type env struct {
	t       *testing.T
	pool    *db.Pool
	clock   *clock
	svc     *triage.Service
	mu      sync.Mutex
	changes []triage.Change
	user    int64
	actor   audit.Actor
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{t: t, pool: d.App, clock: &clock{}}
	e.clock.set(time.Now().UTC())
	e.svc = triage.NewService(triage.Options{Pool: d.App, Comparer: grypeversion.New(), Now: e.clock.Now,
		OnChange: func(_ context.Context, _ *db.OrgTx, cs []triage.Change) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.changes = append(e.changes, cs...)
			return nil
		}})
	if err := d.App.InTx(context.Background(), func(tx *db.Tx) error {
		return tx.QueryRowContext(context.Background(), `INSERT INTO users (email, password_hash)
			VALUES ('analyste@example.org', 'x') RETURNING id`).Scan(&e.user)
	}); err != nil {
		t.Fatal(err)
	}
	e.actor = audit.Actor{UserID: e.user, Email: "analyste@example.org"}
	return e
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

// fixture : une organisation construite ligne par ligne.
type fixture struct {
	e    *env
	org  tenant.OrgID
	blob uuid.UUID
	set  uuid.UUID
	ids  map[string]uuid.UUID
}

func (e *env) newOrg(slug string) *fixture {
	e.t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		e.t.Fatal(err)
	}
	f := &fixture{e: e, org: org, blob: newID(), set: newID(), ids: map[string]uuid.UUID{}}
	f.exec(`WITH o AS (INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, $2, 'fr') RETURNING id)
		INSERT INTO teams (org_id, id, name) SELECT id, id, 'Général' FROM o`, org, slug+"-"+strings.ReplaceAll(org.String()[24:], "-", ""))
	f.exec(`INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content)
		VALUES ($1, $2, sha256('{}'::bytea), 2, 1, '\x00'::bytea)`, org, f.blob)
	f.exec(`INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
		VALUES ($1, $2, sha256('set'::bytea), 0, 0, 0, 0)`, org, f.set)
	vulnerability(e.t, e.pool, cve)
	vulnerability(e.t, e.pool, "CVE-2099-0001")
	return f
}

func (f *fixture) exec(query string, args ...any) {
	f.e.t.Helper()
	if err := f.e.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	}); err != nil {
		f.e.t.Fatalf("%s : %v", query, err)
	}
}

func (f *fixture) id(name string) uuid.UUID {
	f.e.t.Helper()
	id, ok := f.ids[name]
	if !ok {
		f.e.t.Fatalf("identifiant %q inconnu", name)
	}
	return id
}

// project crée un dépôt, sa branche main et un instantané.
func (f *fixture) project(slug string) {
	p, ref, snap := newID(), newID(), newID()
	f.ids[slug], f.ids[slug+"/main"], f.ids["snap:"+slug] = p, ref, snap
	f.exec(`INSERT INTO projects (org_id, id, kind, slug, name, team_id) VALUES ($1, $2, 'repo', $3, $3, $1)`, f.org, p, slug)
	f.exec(`INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main')`,
		f.org, ref, p)
	f.exec(`INSERT INTO snapshots (org_id, id, project_id, ref_id, scanned_at, last_scanned_at, blob_id, set_id, format,
		spec_version, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now(), $5, $6, 'cyclonedx', '1.6', now(), now())`,
		f.org, snap, p, ref, f.blob, f.set)
}

// ref ajoute une branche à un projet, avec son instantané.
func (f *fixture) ref(project, name string) {
	ref, snap := newID(), newID()
	f.ids[project+"/"+name], f.ids["snap:"+project+"/"+name] = ref, snap
	f.exec(`INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', $4)`,
		f.org, ref, f.id(project), name)
	f.exec(`INSERT INTO snapshots (org_id, id, project_id, ref_id, scanned_at, last_scanned_at, blob_id, set_id, format,
		spec_version, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now(), $5, $6, 'cyclonedx', '1.6', now(), now())`,
		f.org, snap, f.id(project), ref, f.blob, f.set)
}

// component crée un composant d'après son purl canonique.
func (f *fixture) component(purl string) uuid.UUID {
	if id, ok := f.ids[purl]; ok {
		return id
	}
	base, ver, _ := strings.Cut(purl, "@")
	typ := strings.TrimPrefix(base, "pkg:")
	typ, _, _ = strings.Cut(typ, "/")
	name := base[strings.LastIndex(base, "/")+1:]
	id := newID()
	f.ids[purl] = id
	f.exec(`INSERT INTO components (org_id, id, purl, purl_base, type, name, version) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		f.org, id, purl, base, typ, name, ver)
	return id
}

func vulnerability(t *testing.T, pool *db.Pool, id string) {
	t.Helper()
	if err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO vulnerabilities (id, source_rank, severity, kev, vulndb_built, updated_at)
			VALUES ($1, 0, 'critical', false, now(), now()) ON CONFLICT DO NOTHING`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// finding crée un constat ouvert du projet (branche main) et renvoie son identifiant.
func (f *fixture) finding(project, purl, vulnID string) uuid.UUID {
	return f.findingOn(project, "main", purl, vulnID)
}

// findingOn crée un constat ouvert sur une branche du projet.
func (f *fixture) findingOn(project, ref, purl, vulnID string) uuid.UUID {
	id := newID()
	snap := "snap:" + project
	if ref != "main" {
		snap += "/" + ref
	}
	f.exec(`INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status, severity, risk, fix_state,
		match_type, first_seen_at, last_seen_at, snapshot_id, vulndb_archive, vulndb_built, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'open', 'critical', 99, 'fixed', 'exact-direct', now(), now(), $7, $8, now(), now())`,
		f.org, id, f.id(project), f.id(project+"/"+ref), f.component(purl), vulnID, f.id(snap), newID())
	return id
}

// status lit le statut effectif enregistré d'un constat.
func (f *fixture) status(findingID uuid.UUID) triage.Status {
	f.e.t.Helper()
	var s string
	if err := f.e.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT triage_status FROM findings WHERE id = $1`, findingID).Scan(&s)
	}); err != nil {
		f.e.t.Fatal(err)
	}
	return triage.Status(s)
}

func (f *fixture) count(query string, args ...any) int {
	f.e.t.Helper()
	var n int
	if err := f.e.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), query, args...).Scan(&n)
	}); err != nil {
		f.e.t.Fatalf("%s : %v", query, err)
	}
	return n
}

// decide prend une décision et échoue le test en cas d'erreur.
func (f *fixture) decide(in triage.Input) triage.Decision {
	f.e.t.Helper()
	if in.Comment == "" {
		in.Comment = "Décision de test."
	}
	d, _, err := f.e.svc.Decide(context.Background(), f.org, f.e.actor, in)
	if err != nil {
		f.e.t.Fatalf("décision %+v : %v", in, err)
	}
	return d
}

func date(t time.Time) *time.Time {
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return &d
}
