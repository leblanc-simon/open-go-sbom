//go:build integration

package vuln_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/vuln"
	"leblanc.io/open-go-sbom/internal/vuln/vulntest"
)

var built1 = time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)

const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

type env struct {
	pool    *db.Pool
	source  *vulntest.Source
	engine  *vulntest.Engine
	checker *vuln.Checker
	dir     string
}

func newEnv(t *testing.T) env {
	t.Helper()
	d := dbtest.New(t)
	e := env{pool: d.App, source: &vulntest.Source{}, engine: &vulntest.Engine{}, dir: t.TempDir()}
	e.checker = vuln.NewChecker(vuln.CheckerOptions{Pool: e.pool, Source: e.source, Engine: e.engine, Dir: e.dir,
		MaxArchive: 1 << 20, ChunkSize: 64})
	return e
}

func (e env) manager(dir string) *vuln.Manager {
	return vuln.NewManager(vuln.ManagerOptions{Pool: e.pool, Engine: e.engine, Dir: dir})
}

func (e env) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.DB().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s : %v", query, err)
	}
	return n
}

func content(t *testing.T, built time.Time, rules ...vulntest.Rule) []byte {
	return vulntest.Archive(t, vulntest.Content{Built: built, Rules: rules})
}

func log4shell() vulntest.Rule {
	return vulntest.Rule{PURL: log4j, Vuln: vuln.Vulnerability{ID: "CVE-2021-44228", Severity: vuln.SeverityCritical,
		KEV: &vuln.KEV{Ransomware: true}}, Match: vuln.Match{FixedVersions: []string{"2.15.0"}, FixState: vuln.FixFixed}}
}

func TestCheckStoresVerifiedArchiveAndSetsTarget(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.manager(t.TempDir()).Ensure(ctx); !errors.Is(err, vuln.ErrNoDatabase) {
		t.Fatalf("sans cible : %v", err)
	}
	body := content(t, built1, log4shell())
	e.source.Publish(body, built1, "")
	a, err := e.checker.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || !a.IsTarget || a.SHA256 != vulntest.SHA256(body) || a.Chunks != (len(body)+63)/64 || !a.Built.Equal(built1) {
		t.Fatalf("archive %+v", a)
	}
	st, err := vuln.ReadState(ctx, e.pool.DB())
	if err != nil || st.Target == nil || st.Target.ID != a.ID || st.LastCheckAt == nil || st.LastCheckError != "" {
		t.Fatalf("état %+v, %v", st, err)
	}
	if n := e.count(t, `SELECT count(*) FROM jobs WHERE kind = $1 AND status = 'pending'`, vuln.RescanAllKind); n != 1 {
		t.Fatalf("%d réanalyses en file", n)
	}
	// La base validée reste installée pour l'instance.
	if _, err := os.Stat(filepath.Join(e.dir, a.ID.String())); err != nil {
		t.Fatalf("installation validée absente : %v", err)
	}
	// Rien de nouveau : ni archive ni réanalyse.
	if again, err := e.checker.Check(ctx); err != nil || again.ID != a.ID {
		t.Fatalf("seconde vérification : %+v, %v", again, err)
	}
	if e.count(t, `SELECT count(*) FROM vulndb_archives`) != 1 || e.count(t, `SELECT count(*) FROM jobs WHERE kind = $1`, vuln.RescanAllKind) != 1 {
		t.Fatal("seconde vérification sans effet attendue")
	}
	// Une liste plus ancienne que la cible n'est pas suivie.
	e.source.Publish(content(t, built1.Add(-time.Hour)), built1.Add(-time.Hour), "")
	if again, err := e.checker.Check(ctx); err != nil || again.ID != a.ID {
		t.Fatalf("liste plus ancienne : %+v, %v", again, err)
	}
	// Nouvelle base : nouvelle cible, la réanalyse en attente est fondue.
	built2 := built1.Add(24 * time.Hour)
	e.source.Publish(content(t, built2), built2, "")
	b, err := e.checker.Check(ctx)
	if err != nil || b.ID == a.ID || !b.IsTarget {
		t.Fatalf("nouvelle base : %+v, %v", b, err)
	}
	if n := e.count(t, `SELECT count(*) FROM jobs WHERE kind = $1`, vuln.RescanAllKind); n != 1 {
		t.Fatalf("%d réanalyses", n)
	}
	list, err := vuln.ListArchives(ctx, e.pool.DB(), 10)
	if err != nil || len(list) != 2 || list[0].ID != b.ID || list[1].IsTarget {
		t.Fatalf("archives %+v, %v", list, err)
	}
	// La liste revient à une archive déjà stockée : elle redevient la cible sans
	// téléchargement.
	e.source.Publish(content(t, built1, log4shell()), built2.Add(time.Hour), vulntest.SHA256(body))
	if c, err := e.checker.Check(ctx); err != nil || c.ID != a.ID {
		t.Fatalf("archive connue : %+v, %v", c, err)
	}
}

// TestCorruptArchivesAreNeverActivated : somme différente, contenu illisible, bloc altéré
// en base.
func TestCorruptArchivesAreNeverActivated(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	body := content(t, built1, log4shell())
	e.source.Publish(body, built1, vulntest.SHA256([]byte("autre chose")))
	if _, err := e.checker.Check(ctx); !errors.Is(err, vuln.ErrChecksum) {
		t.Fatalf("somme différente : %v", err)
	}
	st, _ := vuln.ReadState(ctx, e.pool.DB())
	if st.Target != nil || st.LastCheckError == "" || e.count(t, `SELECT count(*) FROM vulndb_archives`) != 0 {
		t.Fatalf("archive activée malgré sa somme : %+v", st)
	}
	e.source.Publish([]byte("pas une archive"), built1, "")
	if _, err := e.checker.Check(ctx); err == nil {
		t.Fatal("archive illisible acceptée")
	}
	if e.count(t, `SELECT count(*) FROM vulndb_archives`) != 0 {
		t.Fatal("archive illisible stockée")
	}
	e.source.Publish(content(t, built1), built1, "")
	e.source.Fail(errors.New("réseau"))
	if _, err := e.checker.Check(ctx); err == nil {
		t.Fatal("liste injoignable")
	}
	// Archive valide, puis bloc altéré en base : une instance qui synchronise refuse.
	e.source.Publish(body, built1, "")
	a, err := e.checker.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.DB().ExecContext(ctx, `UPDATE vulndb_archive_chunks SET data = 'x' WHERE archive_id = $1 AND seq = 1`, a.ID); err != nil {
		t.Fatal(err)
	}
	m := e.manager(t.TempDir())
	if _, err := m.Ensure(ctx); !errors.Is(err, vuln.ErrChecksum) {
		t.Fatalf("bloc altéré : %v", err)
	}
	if _, ok := m.Loaded(); ok || m.Ready(ctx) == nil {
		t.Fatal("base altérée chargée")
	}
}

// TestSecondInstanceSyncsBeforeMatching : une seconde instance worker se synchronise sur
// la cible depuis PostgreSQL avant de répondre.
func TestSecondInstanceSyncsBeforeMatching(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.source.Publish(content(t, built1, log4shell()), built1, "")
	a, err := e.checker.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir2 := t.TempDir()
	first, second := e.manager(e.dir), e.manager(dir2)
	if _, err := second.Match(ctx, []byte(`{}`)); !errors.Is(err, vuln.ErrNoDatabase) {
		t.Fatalf("avant synchronisation : %v", err)
	}
	for _, m := range []*vuln.Manager{first, second} {
		v, err := m.Ensure(ctx)
		if err != nil || v.ArchiveID != a.ID {
			t.Fatalf("synchronisation : %+v, %v", v, err)
		}
	}
	res, err := second.Match(ctx, []byte(`{"purl": "`+log4j+`"}`))
	if err != nil || len(res.Matches) != 1 || res.Version.ArchiveID != a.ID || res.Vulnerabilities["CVE-2021-44228"].KEV == nil {
		t.Fatalf("correspondance : %+v, %v", res, err)
	}
	built2 := built1.Add(24 * time.Hour)
	e.source.Publish(content(t, built2), built2, "")
	b, err := e.checker.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := second.Loaded(); v.ArchiveID != a.ID {
		t.Fatal("bascule avant synchronisation")
	}
	if v, err := second.Ensure(ctx); err != nil || v.ArchiveID != b.ID {
		t.Fatalf("seconde synchronisation : %+v, %v", v, err)
	}
	// L'ancienne base est fermée et son répertoire supprimé.
	if e.engine.Closed() < 1 {
		t.Fatal("ancienne base restée ouverte")
	}
	if _, err := os.Stat(filepath.Join(dir2, a.ID.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("répertoire de l'ancienne base conservé : %v", err)
	}
	// Une installation locale abîmée est refaite depuis PostgreSQL.
	dir3 := t.TempDir()
	third := e.manager(dir3)
	if err := os.MkdirAll(filepath.Join(dir3, b.ID.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	if v, err := third.Ensure(ctx); err != nil || v.ArchiveID != b.ID {
		t.Fatalf("réinstallation : %+v, %v", v, err)
	}
}

// TestSwapWaitsForRunningMatches : bascule pendant des correspondances en cours ; chacune
// finit sur la base qu'elle a commencée, l'ancienne n'est fermée qu'ensuite.
func TestSwapWaitsForRunningMatches(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.source.Publish(content(t, built1, log4shell()), built1, "")
	a, err := e.checker.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := e.manager(e.dir)
	if _, err := m.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	e.engine.Hook = func(context.Context) {
		started <- struct{}{}
		<-release
	}
	var wg sync.WaitGroup
	results := make(chan vuln.Result, 4)
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			res, err := m.Match(ctx, []byte(`{"purl": "`+log4j+`"}`))
			results <- res
			errs <- err
		})
	}
	for range 4 {
		<-started
	}
	built2 := built1.Add(24 * time.Hour)
	e.source.Publish(content(t, built2), built2, "")
	if _, err := e.checker.Check(ctx); err != nil {
		t.Fatal(err)
	}
	swapped := make(chan vuln.Version)
	go func() {
		e.engine.Hook = nil
		v, err := m.Ensure(ctx)
		if err != nil {
			t.Error(err)
		}
		swapped <- v
	}()
	select {
	case <-swapped:
		t.Fatal("bascule pendant des correspondances en cours")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	v := <-swapped
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("correspondance pendant la bascule : %v", err)
		}
	}
	for r := range results {
		if r.Version.ArchiveID != a.ID || len(r.Matches) != 1 {
			t.Fatalf("résultat %+v", r)
		}
	}
	if v.ArchiveID == a.ID {
		t.Fatal("pas de bascule")
	}
	if res, err := m.Match(ctx, []byte(`{"purl": "`+log4j+`"}`)); err != nil || res.Version.ArchiveID != v.ArchiveID || len(res.Matches) != 0 {
		t.Fatalf("après bascule : %+v, %v", res, err)
	}
}

func TestImportAndRun(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.tar.zst")
	if err := os.WriteFile(path, content(t, built1, log4shell()), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := e.checker.Import(ctx, path)
	if err != nil || a.Origin != vuln.OriginImport || !a.IsTarget {
		t.Fatalf("import : %+v, %v", a, err)
	}
	if again, err := e.checker.Import(ctx, path); err != nil || again.ID != a.ID {
		t.Fatalf("import répété : %+v, %v", again, err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.checker.Import(ctx, path); err == nil {
		t.Fatal("archive vide importée")
	}
	if _, err := e.checker.Import(ctx, filepath.Join(t.TempDir(), "absente")); err == nil {
		t.Fatal("fichier absent importé")
	}
	m := vuln.NewManager(vuln.ManagerOptions{Pool: e.pool, Engine: e.engine, Dir: t.TempDir(), SyncInterval: 10 * time.Millisecond})
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error)
	go func() { done <- m.Run(runCtx) }()
	deadline := time.Now().Add(5 * time.Second)
	for m.Ready(ctx) != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if v, ok := m.Loaded(); !ok || v.ArchiveID != a.ID {
		t.Fatal("Run n'a pas chargé la cible")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Loaded(); ok {
		t.Fatal("base restée ouverte après l'arrêt")
	}
}

func TestCatalog(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	added := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	ghsa := vuln.Vulnerability{ID: "CVE-2021-44228", Namespace: "github:language:java", Severity: vuln.SeverityHigh,
		Description: "GHSA", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}}
	nvd := vuln.Vulnerability{ID: "CVE-2021-44228", Namespace: "nvd:cpe", Severity: vuln.SeverityCritical, Description: "NVD",
		Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, CVSS: []vuln.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N", BaseScore: 10}},
		EPSS: &vuln.EPSS{Score: 0.944, Percentile: 0.999, Date: added}, KEV: &vuln.KEV{DateAdded: &added, Ransomware: true},
		URLs: []string{"https://nvd.nist.gov"}, CWEs: []string{"CWE-502"}, Risk: 99.5}
	upsert := func(v vuln.Vulnerability, built time.Time) {
		t.Helper()
		if err := vuln.UpsertCatalog(ctx, e.pool.DB(), map[string]vuln.Vulnerability{v.ID: v}, built, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	upsert(ghsa, built1)
	upsert(nvd, built1)
	// Une fiche moins fiable, même plus récente, ne remplace pas celle du NVD.
	upsert(ghsa, built1.Add(time.Hour))
	got, err := vuln.GetVulnerability(ctx, e.pool.DB(), "GHSA-jfh8-c2jp-5v3q")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != nvd.ID || got.Description != "NVD" || got.BaseScore() != 10 || got.KEV == nil || !got.KEV.Ransomware ||
		!got.KEV.DateAdded.Equal(added) || got.EPSS == nil || got.EPSS.Score != 0.944 || got.Risk != 99.5 || len(got.CWEs) != 1 {
		t.Fatalf("fiche %+v", got)
	}
	// Une base plus ancienne ne remplace rien.
	older := nvd
	older.Description = "ancienne"
	upsert(older, built1.Add(-time.Hour))
	if got, _ := vuln.GetVulnerability(ctx, e.pool.DB(), nvd.ID); got.Description != "NVD" {
		t.Fatal("fiche remplacée par une base plus ancienne")
	}
	if _, err := vuln.GetVulnerability(ctx, e.pool.DB(), "CVE-0000-0000"); !errors.Is(err, vuln.ErrNotFound) {
		t.Fatalf("fiche absente : %v", err)
	}
	if _, err := vuln.GetArchive(ctx, e.pool.DB(), uuid.New()); !errors.Is(err, vuln.ErrArchiveNotFound) {
		t.Fatalf("archive absente : %v", err)
	}
}
