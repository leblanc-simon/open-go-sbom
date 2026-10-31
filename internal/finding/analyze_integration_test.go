//go:build integration

package finding

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/inventory"
	"leblanc.io/open-go-sbom/internal/jobs"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/internal/vuln"
	"leblanc.io/open-go-sbom/internal/vuln/vulntest"
)

// TestLog4ShellFindingIsKEV : un SBOM contenant log4j-core 2.14.1 produit un constat
// CVE-2021-44228 marqué KEV ; l'analyse répétée ne change rien (idempotence).
func TestLog4ShellFindingIsKEV(t *testing.T) {
	e := newEnv(t)
	e.push(testdata(t, "log4shell.cdx16.json"))
	if out := e.analyze(e.org, e.main); out != OutcomeNoDatabase {
		t.Fatalf("sans base : %s", out)
	}
	a := e.publish(built1, log4shellRule())
	if out := e.analyze(e.org, e.main); out != OutcomeAnalyzed {
		t.Fatalf("issue %s", out)
	}
	f, ok := e.finding(log4jOld, "CVE-2021-44228")
	if !ok || f.Status != StatusOpen || !f.KEV || f.Severity != "critical" || f.Archive != a.ID || f.Events != 1 {
		t.Fatalf("constat %+v (%v)", f, ok)
	}
	if out := e.analyze(e.org, e.main); out != OutcomeUpToDate {
		t.Fatalf("seconde analyse : %s", out)
	}
	// Rejouer le handler du job (au moins une fois) ne crée rien non plus.
	payload, _ := json.Marshal(inventory.AnalysisPayload{RefID: e.main})
	if err := e.analyzer.Handler().Handle(context.Background(), jobs.Execution{OrgID: e.org, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM findings`); n != 1 {
		t.Fatalf("%d constats", n)
	}
	if n := e.count(`SELECT count(*) FROM finding_events`); n != 1 {
		t.Fatalf("%d événements", n)
	}
	matched := e.count(`SELECT match_count FROM ref_analyses WHERE ref_id = $1`, e.main)
	unmatched := e.count(`SELECT unmatched_count FROM ref_analyses WHERE ref_id = $1`, e.main)
	if matched != 1 || unmatched != 0 {
		t.Fatalf("état d'analyse : %d / %d", matched, unmatched)
	}
	if err := e.analyzer.Handler().Handle(context.Background(), jobs.Execution{Payload: payload}); !jobs.IsPermanent(err) {
		t.Fatalf("job sans organisation : %v", err)
	}
}

// TestUpdateResolvesAndReappearanceReopens : un composant mis à jour résout ses constats ;
// la version vulnérable revient : le même constat est rouvert, historique conservé ; une
// base qui ne juge plus un composant vulnérable résout son constat.
func TestUpdateResolvesAndReappearanceReopens(t *testing.T) {
	e := newEnv(t)
	e.publish(built1, log4shellRule(), apiRule())
	e.push(testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	if _, ok := e.finding(apiOld, "CVE-2099-0001"); !ok {
		t.Fatal("constat log4j-api attendu")
	}

	e.push(sbomWith(t, "2.17.1"))
	if out := e.analyze(e.org, e.main); out != OutcomeAnalyzed {
		t.Fatalf("issue %s", out)
	}
	f, _ := e.finding(log4jOld, "CVE-2021-44228")
	if f.Status != StatusResolved || f.Resolution != string(ResolutionComponentRemoved) || f.Events != 2 {
		t.Fatalf("après mise à jour : %+v", f)
	}
	if f, _ := e.finding(apiOld, "CVE-2099-0001"); f.Status != StatusOpen {
		t.Fatalf("log4j-api inchangé : %+v", f)
	}

	e.push(sbomWith(t, "2.14.1"))
	e.analyze(e.org, e.main)
	f, _ = e.finding(log4jOld, "CVE-2021-44228")
	if f.Status != StatusOpen || f.Resolution != "" || f.Events != 3 {
		t.Fatalf("après retour de la version vulnérable : %+v", f)
	}
	if n := e.count(`SELECT count(*) FROM findings WHERE vuln_id = 'CVE-2021-44228'`); n != 1 {
		t.Fatalf("%d constats pour le même couple", n)
	}

	// Nouvelle base sans la fiche de log4j-api : constat résolu, composant toujours là.
	b := e.publish(built1.Add(24*time.Hour), log4shellRule())
	e.analyze(e.org, e.main)
	f, _ = e.finding(apiOld, "CVE-2099-0001")
	if f.Status != StatusResolved || f.Resolution != string(ResolutionNotMatched) || f.Archive != b.ID {
		t.Fatalf("fiche retirée : %+v", f)
	}
	if f, _ := e.finding(log4jOld, "CVE-2021-44228"); f.Archive != b.ID || f.Status != StatusOpen {
		t.Fatalf("version de base notée : %+v", f)
	}
}

// TestNewTargetRescansEachActiveRefOnce : une nouvelle cible met en file une seule
// réanalyse par référence active, fondue avec une analyse déjà en attente ; références
// retirées, projets archivés et organisations archivées sont écartés.
func TestNewTargetRescansEachActiveRefOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.push(testdata(t, "log4shell.cdx16.json"))
	org2, agent2, repo2, main2 := e.newOrg("autre")
	e.ingestIn(org2, agent2, repo2, testdata(t, "log4shell.cdx16.json"))
	// Une seconde branche, puis retirée ; un projet archivé ; une organisation archivée.
	org3, _, _, _ := e.newOrg("archive")
	e.execIn(org3, `UPDATE organizations SET archived_at = now()`)
	ref3 := newID()
	e.execIn(e.org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name, removed_at)
		VALUES ($1, $2, $3, 'repo', 'branch', 'old', now())`, e.org, ref3, e.repo)
	archivedRepo, archivedRef := newID(), newID()
	e.execIn(e.org, `INSERT INTO projects (org_id, id, kind, slug, name, archived_at) VALUES ($1, $2, 'repo', 'vieux', 'vieux', now())`,
		e.org, archivedRepo)
	e.execIn(e.org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main')`,
		e.org, archivedRef, archivedRepo)

	// Les ingestions ont chacune mis en file une analyse en priorité haute.
	if n := e.jobs(t, inventory.AnalysisKind); n != 2 {
		t.Fatalf("%d analyses en file après ingestion", n)
	}
	e.publish(built1, log4shellRule())
	if n := e.jobs(t, vuln.RescanAllKind); n != 1 {
		t.Fatalf("%d réanalyses du parc", n)
	}
	n, err := e.analyzer.RescanAll(ctx)
	if err != nil || n != 2 {
		t.Fatalf("%d organisations, %v", n, err)
	}
	for _, org := range []tenant.OrgID{e.org, org2} {
		if _, err := e.analyzer.RescanOrg(ctx, jobs.Execution{OrgID: org}); err != nil {
			t.Fatal(err)
		}
	}
	var refs []string
	rows, err := e.pool.DB().QueryContext(ctx, `SELECT payload->>'ref_id', priority FROM jobs WHERE kind = $1 AND status = 'pending'`,
		inventory.AnalysisKind)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ref string
		var prio int
		if err := rows.Scan(&ref, &prio); err != nil {
			t.Fatal(err)
		}
		if prio != jobs.PriorityHigh {
			t.Errorf("priorité d'une ingestion fraîche abaissée : %d", prio)
		}
		refs = append(refs, ref)
	}
	_ = rows.Close()
	if len(refs) != 2 {
		t.Fatalf("analyses en file : %v", refs)
	}
	// Seconde exécution (au moins une fois) : rien de plus.
	if _, err := e.analyzer.RescanAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.analyzer.RescanOrg(ctx, jobs.Execution{OrgID: e.org}); err != nil {
		t.Fatal(err)
	}
	if n := e.jobs(t, inventory.AnalysisKind); n != 2 {
		t.Fatalf("%d analyses après rejeu", n)
	}
	// Une fois les analyses faites, la réanalyse les remet en file en priorité basse, et
	// l'analyse ne refait rien.
	e.analyze(e.org, e.main)
	e.analyze(org2, main2)
	if _, err := e.pool.DB().ExecContext(ctx, `UPDATE jobs SET status = 'done', finished_at = now() WHERE kind = $1`,
		inventory.AnalysisKind); err != nil {
		t.Fatal(err)
	}
	if _, err := e.analyzer.RescanOrg(ctx, jobs.Execution{OrgID: e.org}); err != nil {
		t.Fatal(err)
	}
	if n := e.jobs(t, inventory.AnalysisKind); n != 1 {
		t.Fatalf("%d analyses en file", n)
	}
	if out := e.analyze(e.org, e.main); out != OutcomeUpToDate {
		t.Fatalf("réanalyse avec la même base : %s", out)
	}
}

func (e *env) jobs(t *testing.T, kind string) int {
	t.Helper()
	var n int
	if err := e.pool.DB().QueryRowContext(context.Background(),
		`SELECT count(*) FROM jobs WHERE kind = $1 AND status = 'pending'`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestLateWorkerSyncsBeforeAnalyzing : avec deux instances worker, la seconde, restée sur
// l'ancienne base, se synchronise sur la cible avant d'analyser.
func TestLateWorkerSyncsBeforeAnalyzing(t *testing.T) {
	e := newEnv(t)
	e.publish(built1, log4shellRule(), apiRule())
	e.push(testdata(t, "log4shell.cdx16.json"))
	other := vuln.NewManager(vuln.ManagerOptions{Pool: e.pool, Engine: e.engine, Dir: t.TempDir()})
	if _, err := other.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := e.publish(built1.Add(24*time.Hour), log4shellRule())
	late := NewAnalyzer(Options{Pool: e.pool, Engine: other, Blobs: e.ingest})
	if _, err := late.Analyze(context.Background(), e.org, e.main); err != nil {
		t.Fatal(err)
	}
	if v, _ := other.Loaded(); v.ArchiveID != b.ID {
		t.Fatal("le worker en retard n'a pas synchronisé")
	}
	if f, _ := e.finding(log4jOld, "CVE-2021-44228"); f.Archive != b.ID {
		t.Fatalf("constat de l'ancienne base : %+v", f)
	}
	if _, ok := e.finding(apiOld, "CVE-2099-0001"); ok {
		t.Fatal("constat d'une fiche absente de la cible")
	}
}

// TestTargetChangesDuringMatch : la cible change pendant la correspondance ; l'analyse
// recommence avec la nouvelle base au lieu d'écrire un résultat périmé.
func TestTargetChangesDuringMatch(t *testing.T) {
	e := newEnv(t)
	e.publish(built1, log4shellRule(), apiRule())
	e.push(testdata(t, "log4shell.cdx16.json"))
	var b vuln.Archive
	once := false
	e.engine.Hook = func(context.Context) {
		if once {
			return
		}
		once = true
		e.source.Publish(vulntest.Archive(t, vulntest.Content{Built: built1.Add(time.Hour), Rules: []vulntest.Rule{log4shellRule()}}),
			built1.Add(time.Hour), "")
		a, err := e.checker.Check(context.Background())
		if err != nil {
			t.Error(err)
			return
		}
		b = *a
	}
	if out := e.analyze(e.org, e.main); out != OutcomeAnalyzed {
		t.Fatalf("issue %s", out)
	}
	if f, _ := e.finding(log4jOld, "CVE-2021-44228"); f.Archive != b.ID {
		t.Fatalf("résultat de la base remplacée écrit : %+v", f)
	}
	if _, ok := e.finding(apiOld, "CVE-2099-0001"); ok {
		t.Fatal("constat de la base remplacée")
	}
}

// TestInventoryChangesDuringMatch : un nouvel instantané arrive pendant la
// correspondance ; l'analyse s'efface devant celle qu'il a mise en file.
func TestInventoryChangesDuringMatch(t *testing.T) {
	e := newEnv(t)
	e.publish(built1, log4shellRule())
	e.push(testdata(t, "log4shell.cdx16.json"))
	once := false
	e.engine.Hook = func(context.Context) {
		if !once {
			once = true
			e.push(sbomWith(t, "2.17.1"))
		}
	}
	if out := e.analyze(e.org, e.main); out != OutcomeSuperseded {
		t.Fatalf("issue %s", out)
	}
	if n := e.count(`SELECT count(*) FROM findings`); n != 0 {
		t.Fatalf("%d constats d'un inventaire remplacé", n)
	}
	if out := e.analyze(e.org, e.main); out != OutcomeAnalyzed {
		t.Fatalf("seconde analyse : %s", out)
	}
	if n := e.count(`SELECT count(*) FROM findings`); n != 0 {
		t.Fatalf("log4j-core 2.17.1 : %d constats", n)
	}
}

func TestAnalyzeEdgeCases(t *testing.T) {
	e := newEnv(t)
	e.publish(built1, log4shellRule())
	if out := e.analyze(e.org, e.main); out != OutcomeNoInventory {
		t.Fatalf("sans instantané : %s", out)
	}
	if out := e.analyze(e.org, newID()); out != OutcomeUnknownRef {
		t.Fatalf("référence inconnue : %s", out)
	}
	// Une référence d'une autre organisation est inconnue (RLS).
	org2, _, _, main2 := e.newOrg("autre")
	_ = org2
	if out := e.analyze(e.org, main2); out != OutcomeUnknownRef {
		t.Fatalf("référence d'une autre organisation : %s", out)
	}
}
