//go:build integration

package dashboard

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// now est l'instant des jeux construits à la main.
var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// clock est une horloge de test réglable.
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
	c.t = t
}

// fixture construit un jeu de données à la main, ligne par ligne, dans une organisation.
type fixture struct {
	t    *testing.T
	pool *db.Pool
	org  tenant.OrgID
	blob uuid.UUID
	set  uuid.UUID
	ids  map[string]uuid.UUID
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func newFixture(t *testing.T, pool *db.Pool, slug string) *fixture {
	t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, pool: pool, org: org, blob: newID(), set: newID(), ids: map[string]uuid.UUID{}}
	f.exec(`INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, $2, 'fr')`, org, slug)
	f.exec(`INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content)
		VALUES ($1, $2, sha256('{}'::bytea), 2, 1, '\x00'::bytea)`, org, f.blob)
	f.exec(`INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
		VALUES ($1, $2, sha256('set'::bytea), 0, 0, 0, 0)`, org, f.set)
	return f
}

func (f *fixture) exec(query string, args ...any) {
	f.t.Helper()
	if err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s : %v", query, err)
	}
}

func (f *fixture) id(name string) uuid.UUID {
	f.t.Helper()
	id, ok := f.ids[name]
	if !ok {
		f.t.Fatalf("identifiant %q inconnu", name)
	}
	return id
}

func (f *fixture) name(name string) uuid.UUID {
	id := newID()
	f.ids[name] = id
	return id
}

// agent crée un agent ; seen (facultatif) est son dernier contact.
func (f *fixture) agent(name, kind string, seen *time.Time, disabled bool) {
	var dis any
	if disabled {
		dis = now.Add(-24 * time.Hour)
	}
	f.exec(`INSERT INTO agents (org_id, id, kind, name, last_seen_at, disabled_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		f.org, f.name(name), kind, name, seen, dis)
}

// project crée un projet et sa référence « main » (ou « host »).
func (f *fixture) project(slug, kind string, archived bool) {
	var arch any
	if archived {
		arch = now.Add(-24 * time.Hour)
	}
	f.exec(`INSERT INTO projects (org_id, id, kind, slug, name, archived_at) VALUES ($1, $2, $3, $4, $4, $5)`,
		f.org, f.name(slug), kind, slug, arch)
	ref := "main"
	if kind == "host" {
		ref = "host"
	}
	f.ref(slug, ref, false)
}

// ref crée une référence d'un projet ; removed la retire.
func (f *fixture) ref(project, name string, removed bool) {
	p := f.id(project)
	kind := "branch"
	if name == "host" {
		kind = "host"
	}
	var rem any
	if removed {
		rem = now.Add(-24 * time.Hour)
	}
	var pkind string
	if err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT kind FROM projects WHERE id = $1`, p).Scan(&pkind)
	}); err != nil {
		f.t.Fatal(err)
	}
	ref, snap := f.name(project+"/"+name), f.name("snap:"+project+"/"+name)
	f.exec(`INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name, removed_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		f.org, ref, p, pkind, kind, name, rem)
	f.exec(`INSERT INTO snapshots (org_id, id, project_id, ref_id, scanned_at, last_scanned_at, blob_id, set_id, format,
		spec_version, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, 'cyclonedx', '1.6', $5, $5)`,
		f.org, snap, p, ref, now.Add(-time.Hour), f.blob, f.set)
}

// component crée un composant de purl pkg:<base>@<version>.
func (f *fixture) component(name, base, version string) {
	f.exec(`INSERT INTO components (org_id, id, purl, purl_base, type, name, version) VALUES ($1, $2, $3, $4, 'npm', $5, $6)`,
		f.org, f.name(name), base+"@"+version, base, name, version)
}

// vuln ajoute une vulnérabilité au catalogue global.
func vulnerability(t *testing.T, pool *db.Pool, id, severity string, kev bool) {
	t.Helper()
	if err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO vulnerabilities (id, source_rank, severity, kev, vulndb_built, updated_at)
			VALUES ($1, 0, $2, $3, now(), now()) ON CONFLICT DO NOTHING`, id, severity, kev)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// finding crée un constat sur la référence ref (« projet/nom ») ; resolved nul : ouvert.
func (f *fixture) finding(ref, component, vulnID, severity string, kev bool, risk float64, firstSeen time.Time, resolved *time.Time) {
	r := f.id(ref)
	var project uuid.UUID
	if err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT project_id FROM tracked_refs WHERE id = $1`, r).Scan(&project)
	}); err != nil {
		f.t.Fatal(err)
	}
	status, resolution := "open", any(nil)
	if resolved != nil {
		status, resolution = "resolved", "component_removed"
	}
	last := firstSeen
	if resolved != nil {
		last = *resolved
	}
	f.exec(`INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status, resolution, severity, kev, risk,
		fix_state, match_type, first_seen_at, last_seen_at, resolved_at, snapshot_id, vulndb_archive, vulndb_built, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'fixed', 'exact-direct', $12, $13, $14, $15, $16, now(), now())`,
		f.org, newID(), project, r, f.id(component), vulnID, status, resolution, severity, kev, risk, firstSeen, last, resolved,
		f.id("snap:"+ref), newID())
}

// analysis enregistre la dernière analyse d'une référence.
func (f *fixture) analysis(ref string, at time.Time) {
	r := f.id(ref)
	f.exec(`INSERT INTO ref_analyses (org_id, ref_id, project_id, set_id, snapshot_id, vulndb_archive, vulndb_built, analyzed_at,
		match_count, unmatched_count)
		SELECT org_id, id, project_id, $2, $3, $4, now(), $5, 0, 0 FROM tracked_refs WHERE id = $1`,
		r, f.set, f.id("snap:"+ref), newID(), at)
}

func ago(d time.Duration) *time.Time {
	t := now.Add(-d)
	return &t
}

const day24 = 24 * time.Hour

// reference construit le jeu de référence des tests d'agrégats (voir TestOrgIndicators
// pour les valeurs attendues).
func reference(t *testing.T, pool *db.Pool, slug string) *fixture {
	t.Helper()
	vulnerability(t, pool, "CVE-2021-44228", "critical", true)
	vulnerability(t, pool, "CVE-2099-0002", "high", false)
	vulnerability(t, pool, "CVE-2099-0003", "medium", false)
	vulnerability(t, pool, "CVE-2099-0004", "low", false)
	f := newFixture(t, pool, slug)
	f.agent("srv-agent", "host", ago(8*day24), false)   // muet (plus de 7 jours)
	f.agent("repo-agent", "repo", ago(6*day24), false)  // actif
	f.agent("old-agent", "host", ago(30*day24), true)   // désactivé : ni muet ni compté
	f.agent("new-agent", "host", nil, false)            // jamais vu : en attente
	f.agent("lost-agent", "repo", ago(20*day24), false) // muet depuis plus longtemps
	f.project("api", "repo", false)
	f.ref("api", "dev", true) // retirée : ses constats ne comptent pas
	f.project("srv", "host", false)
	f.project("old", "repo", true) // archivé : ses constats ne comptent pas
	f.project("quiet", "repo", false)
	f.component("lodash-20", "pkg:npm/lodash", "4.17.20")
	f.component("lodash-15", "pkg:npm/lodash", "4.17.15")
	f.component("openssl", "pkg:deb/debian/openssl", "3.0.11")
	f.component("log4j", "pkg:maven/org.apache.logging.log4j/log4j-core", "2.14.1")

	// Ouverts, comptés.
	f.finding("api/main", "lodash-20", "CVE-2099-0002", "high", false, 70, now.Add(-40*day24), nil)
	f.finding("api/main", "log4j", "CVE-2021-44228", "critical", true, 99, now.Add(-3*day24), nil)
	f.finding("api/main", "openssl", "CVE-2099-0003", "medium", false, 40, now.Add(-50*day24), nil)
	f.finding("srv/host", "openssl", "CVE-2099-0003", "medium", false, 45, now.Add(-50*day24), nil)
	f.finding("srv/host", "lodash-15", "CVE-2099-0004", "low", false, 10, now.Add(-50*day24), nil)
	// Ouverts, exclus : référence retirée, projet archivé.
	f.finding("api/dev", "lodash-20", "CVE-2099-0002", "high", false, 70, now.Add(-40*day24), nil)
	f.finding("old/main", "log4j", "CVE-2021-44228", "critical", true, 99, now.Add(-40*day24), nil)
	// Résolus : critique en 8 jours, moyen en 15 jours, élevé aujourd'hui en 35 heures,
	// faible hors de la période de 90 jours, élevé d'un projet archivé (exclu).
	f.finding("srv/host", "log4j", "CVE-2021-44228", "critical", true, 99, now.Add(-10*day24), ago(2*day24))
	f.finding("api/main", "lodash-15", "CVE-2099-0003", "medium", false, 40, now.Add(-20*day24), ago(5*day24))
	f.finding("srv/host", "lodash-20", "CVE-2099-0002", "high", false, 70, now.Add(-36*time.Hour), ago(time.Hour))
	f.finding("api/main", "lodash-15", "CVE-2099-0004", "low", false, 10, now.Add(-100*day24), ago(95*day24))
	f.finding("old/main", "lodash-20", "CVE-2099-0002", "high", false, 70, now.Add(-3*day24), ago(day24))
	f.analysis("api/main", now.Add(-3*time.Hour))
	f.analysis("srv/host", now.Add(-2*time.Hour))
	return f
}

func newDB(t *testing.T) (*db.Pool, *clock, *Service) {
	t.Helper()
	d := dbtest.New(t)
	c := &clock{t: now}
	return d.App, c, NewService(d.App, WithClock(c.Now))
}
