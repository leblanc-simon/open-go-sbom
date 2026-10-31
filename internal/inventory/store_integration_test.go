//go:build integration

package inventory

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/sbom"
)

func (f fixture) analysisJobs(t *testing.T, ref uuid.UUID) int {
	return f.count(t, `SELECT count(*) FROM jobs WHERE kind = $1 AND org_id = $2 AND payload->>'ref_id' = $3`,
		AnalysisKind, f.org, ref.String())
}

// Critère : deux commits successifs d'un dépôt sans changement de dépendances donnent deux
// instantanés et un seul ensemble d'inventaire.
func TestRepoTwoCommitsShareSet(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	cs := components(3, "1.0.0")
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	first := f.store(t, f.repoRecord(commit(1), cs, t0))
	second := f.store(t, f.repoRecord(commit(2), cs, t0.Add(time.Minute)))
	if first.Outcome != OutcomeCreated || second.Outcome != OutcomeCreated || !first.SetCreated || second.SetCreated {
		t.Fatalf("résultats %+v / %+v", first, second)
	}
	if first.SetID != second.SetID || first.SnapshotID == second.SnapshotID {
		t.Fatal("deux commits identiques : un ensemble, deux instantanés attendus")
	}
	if !first.CurrentChanged || second.CurrentChanged {
		t.Errorf("ensemble courant changé : %v puis %v", first.CurrentChanged, second.CurrentChanged)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots`); n != 2 {
		t.Errorf("%d instantanés", n)
	}
	if n := f.count(t, `SELECT count(*) FROM component_sets`); n != 1 {
		t.Errorf("%d ensembles", n)
	}
	if n := f.count(t, `SELECT count(*) FROM ref_current WHERE snapshot_id = $1`, second.SnapshotID); n != 1 {
		t.Error("le second commit doit être courant")
	}
	if n := f.analysisJobs(t, f.main); n != 1 {
		t.Errorf("%d jobs d'analyse, attendu 1", n)
	}
}

// Ré-ingérer le même SBOM pour la même référence et le même commit ne crée rien.
func TestRepoSameCommitIsIdempotent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	cs := components(2, "1.0.0")
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	first := f.store(t, f.repoRecord(commit(1), cs, t0))
	again := f.store(t, f.repoRecord(commit(1), cs, t0.Add(time.Minute)))
	if again.Outcome != OutcomeUnchanged || again.SnapshotID != first.SnapshotID || again.CurrentChanged || again.SetCreated {
		t.Fatalf("rejeu %+v", again)
	}
	for table, want := range map[string]int{"snapshots": 1, "component_sets": 1, "components": 2, "component_set_items": 2} {
		if n := f.count(t, `SELECT count(*) FROM `+table); n != want {
			t.Errorf("%s : %d lignes, attendu %d", table, n, want)
		}
	}
	// Même commit, autre inventaire : l'ensemble de l'instantané est remplacé.
	replaced := f.store(t, f.repoRecord(commit(1), components(2, "1.1.0"), t0.Add(2*time.Minute)))
	if replaced.Outcome != OutcomeReplaced || replaced.SnapshotID != first.SnapshotID || !replaced.CurrentChanged {
		t.Fatalf("remplacement %+v", replaced)
	}
	if n := f.count(t, `SELECT count(*) FROM ref_current WHERE set_id = $1`, replaced.SetID); n != 1 {
		t.Error("ref_current n'a pas suivi le nouvel ensemble")
	}
}

// Critère : deux envois identiques d'un hôte donnent un seul instantané ; la date de
// dernière analyse avance.
func TestHostIdenticalScansUpdateDate(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	cs := components(3, "1.0.0")
	t0 := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Microsecond)
	first := f.store(t, f.hostRecord(cs, t0))
	second := f.store(t, f.hostRecord(cs, t0.Add(24*time.Hour)))
	if second.Outcome != OutcomeUnchanged || second.SnapshotID != first.SnapshotID || second.CurrentChanged {
		t.Fatalf("second envoi %+v", second)
	}
	var scanned, last time.Time
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT scanned_at, last_scanned_at FROM snapshots WHERE id = $1`,
			first.SnapshotID).Scan(&scanned, &last)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !scanned.Equal(t0) || !last.Equal(t0.Add(24*time.Hour)) {
		t.Errorf("dates %s, %s", scanned, last)
	}
	// Un envoi identique plus ancien ne recule pas la date.
	f.store(t, f.hostRecord(cs, t0.Add(time.Hour)))
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE last_scanned_at = $1`, t0.Add(24*time.Hour)); n != 1 {
		t.Error("date de dernière analyse reculée")
	}
	third := f.store(t, f.hostRecord(components(4, "1.0.0"), t0.Add(25*time.Hour)))
	if third.Outcome != OutcomeCreated || !third.CurrentChanged || third.SnapshotID == first.SnapshotID {
		t.Fatalf("inventaire changé %+v", third)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE ref_id = $1`, f.hostRef); n != 2 {
		t.Errorf("%d instantanés d'hôte", n)
	}
}

// Un envoi plus ancien que l'instantané courant (traité en retard) ne devient pas courant.
func TestOlderScanDoesNotBecomeCurrent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	newest := f.store(t, f.repoRecord(commit(2), components(2, "2.0.0"), t0))
	older := f.store(t, f.repoRecord(commit(1), components(2, "1.0.0"), t0.Add(-time.Minute)))
	if older.Outcome != OutcomeCreated || older.CurrentChanged {
		t.Fatalf("envoi en retard %+v", older)
	}
	if n := f.count(t, `SELECT count(*) FROM ref_current WHERE snapshot_id = $1`, newest.SnapshotID); n != 1 {
		t.Error("l'instantané courant a reculé")
	}
	// Le rejeu identique d'un commit ancien, même daté de maintenant, ne le rend pas courant.
	f.store(t, f.repoRecord(commit(1), components(2, "1.0.0"), time.Now()))
	if n := f.count(t, `SELECT count(*) FROM ref_current WHERE snapshot_id = $1`, newest.SnapshotID); n != 1 {
		t.Error("un rejeu a rendu courant un commit ancien")
	}
}

// Critère : un même purl dans deux organisations donne deux lignes components distinctes.
func TestComponentsArePerOrganization(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	a, b := newFixture(t, tdb.App), newFixture(t, tdb.App)
	cs := components(1, "1.0.0")
	a.store(t, a.repoRecord(commit(1), cs, time.Now()))
	b.store(t, b.repoRecord(commit(1), cs, time.Now()))
	var ids []uuid.UUID
	for _, f := range []fixture{a, b} {
		err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
			var id uuid.UUID
			err := tx.QueryRowContext(context.Background(), `SELECT id FROM components WHERE purl = $1`, cs[0].PURL).Scan(&id)
			ids = append(ids, id)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if ids[0] == ids[1] {
		t.Fatal("composant partagé entre organisations")
	}
	var total int
	if err := tdb.Owner(t).QueryRow(`SELECT count(*) FROM components WHERE purl = $1`, cs[0].PURL).Scan(&total); err != nil || total != 2 {
		t.Errorf("%d lignes components pour le purl, %v", total, err)
	}
}

func TestComponentsAccumulateCPEsAndHashes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	one := sbom.Normalize(sbom.RawDocument{Components: []sbom.RawComponent{{PURL: "pkg:npm/a@1",
		CPEs: []string{"cpe:2.3:a:a:a:1:*:*:*:*:*:*:*"}}}}).Components
	two := sbom.Normalize(sbom.RawDocument{Components: []sbom.RawComponent{{PURL: "pkg:npm/a@1",
		CPEs:   []string{"cpe:2.3:a:b:a:1:*:*:*:*:*:*:*"},
		Hashes: []sbom.RawHash{{Algorithm: "SHA-1", Value: "0123456789abcdef0123456789abcdef01234567"}}}}}).Components
	r1 := f.store(t, f.repoRecord(commit(1), one, time.Now()))
	r2 := f.store(t, f.repoRecord(commit(2), two, time.Now()))
	if r1.SetID != r2.SetID {
		t.Error("CPE et empreintes ne font pas partie de l'ensemble")
	}
	var cpes, hashes []string
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT cpes, hashes FROM components`).Scan(db.Array(&cpes), db.Array(&hashes))
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cpes, []string{"cpe:2.3:a:a:a:1:*:*:*:*:*:*:*", "cpe:2.3:a:b:a:1:*:*:*:*:*:*:*"}) || len(hashes) != 1 {
		t.Errorf("CPE %v, empreintes %v", cpes, hashes)
	}
}

func TestStoreRejectsUnknownRefAndBadCommit(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f, other := newFixture(t, tdb.App), newFixture(t, tdb.App)
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		r := f.repoRecord(commit(1), nil, time.Now())
		r.RefID = other.main // référence d'une autre organisation : invisible
		_, err := Store(context.Background(), tx, r, time.Now())
		return err
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("référence d'une autre organisation : %v", err)
	}
	err = f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		_, err := Store(context.Background(), tx, f.repoRecord("", nil, time.Now()), time.Now())
		return err
	})
	if err == nil {
		t.Error("dépôt sans commit accepté")
	}
	err = f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		r := f.hostRecord(nil, time.Now())
		r.Commit = commit(1)
		_, err := Store(context.Background(), tx, r, time.Now())
		return err
	})
	if err == nil {
		t.Error("hôte avec commit accepté")
	}
}

// Un inventaire vide est un inventaire : un instantané, un ensemble vide.
func TestEmptyInventory(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	res := f.store(t, f.hostRecord([]sbom.Component{}, time.Now()))
	if res.Outcome != OutcomeCreated || !res.SetCreated {
		t.Fatalf("%+v", res)
	}
}

// Ingestions concurrentes d'une même organisation, composants communs et références
// distinctes ou communes : ni interblocage, ni doublon, un seul ensemble par inventaire.
func TestConcurrentStores(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	shared := components(300, "1.0.0")
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Inventaire propre au worker (composants communs + un composant à lui), sur la
			// même référence d'hôte ou sur le dépôt.
			own := sbom.Normalize(sbom.RawDocument{Components: []sbom.RawComponent{{PURL: "pkg:npm/propre@" + commit(i)[36:]}}}).Components
			cs := append(slices.Clone(shared), own...)
			slices.SortFunc(cs, func(a, b sbom.Component) int { return compare(a.PURL, b.PURL) })
			for _, r := range []Record{f.repoRecord(commit(100+i), cs, time.Now()), f.hostRecord(shared, time.Now())} {
				err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
					_, err := Store(context.Background(), tx, r, time.Now())
					return err
				})
				if err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := f.count(t, `SELECT count(*) FROM components`); n != 300+workers {
		t.Errorf("%d composants", n)
	}
	if n := f.count(t, `SELECT count(*) FROM component_sets`); n != workers+1 {
		t.Errorf("%d ensembles, attendu %d", n, workers+1)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE ref_id = $1`, f.hostRef); n != 1 {
		t.Errorf("%d instantanés d'hôte pour un inventaire identique", n)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE ref_id = $1`, f.main); n != workers {
		t.Errorf("%d instantanés de dépôt", n)
	}
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Mesure : rangement d'un inventaire de 5 000 composants (premier envoi, puis envoi d'un
// nouveau commit au même inventaire).
func TestStoreFiveThousandComponents(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	cs := components(5000, "1.0.0")
	start := time.Now()
	first := f.store(t, f.repoRecord(commit(1), cs, time.Now()))
	firstDur := time.Since(start)
	start = time.Now()
	second := f.store(t, f.repoRecord(commit(2), cs, time.Now()))
	t.Logf("5 000 composants : premier rangement %s, commit suivant au même inventaire %s", firstDur, time.Since(start))
	if !first.SetCreated || second.SetCreated || f.count(t, `SELECT count(*) FROM component_set_items`) != 5000 {
		t.Fatal("rangement incomplet")
	}
}
