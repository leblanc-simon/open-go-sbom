//go:build integration

package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/version/grypeversion"
)

func newHistory(t *testing.T, pool *db.Pool, p RetentionPolicy, now time.Time) *History {
	t.Helper()
	h, err := NewHistory(HistoryOptions{Pool: pool, Comparer: grypeversion.New(), Retention: p,
		Clock: jobs.ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// inventoryOf construit un inventaire npm normalisé à partir de couples nom@version.
func inventoryOf(pkgs ...string) []sbom.Component {
	raw := sbom.RawDocument{Format: sbom.FormatCycloneDX, SpecVersion: "1.6"}
	for _, p := range pkgs {
		raw.Components = append(raw.Components, sbom.RawComponent{PURL: "pkg:npm/" + p})
	}
	return sbom.Normalize(raw).Components
}

// storeAt range un instantané de dépôt scanné et reçu à la date at.
func (f fixture) storeAt(t *testing.T, n int, cs []sbom.Component, at time.Time, blob uuid.UUID) Result {
	t.Helper()
	r := f.repoRecord(commit(n), cs, at)
	r.BlobID = blob
	var res Result
	if err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		var err error
		res, err = Store(context.Background(), tx, r, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return res
}

func (f fixture) newBlob(t *testing.T) uuid.UUID {
	t.Helper()
	id := newID()
	f.exec(t, `INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content) VALUES ($1, $2, sha256($3::bytea), 2, 1, '\x00'::bytea)`,
		f.org, id, []byte(id.String()))
	return id
}

func diffJobs(t *testing.T, f fixture, ref uuid.UUID) int {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM jobs WHERE kind = $1 AND org_id = $2 AND payload->>'ref_id' = $3`,
		DiffKind, f.org.UUID(), ref.String())
}

// TestDiffsOfConsecutiveSnapshots : chaque instantané créé met en file le calcul des
// différences de sa référence ; le job les enregistre une fois par couple d'ensembles ;
// la frise lit les comptes depuis le précédent ; la comparaison lit la différence
// enregistrée, ou la calcule à la demande pour un couple quelconque.
func TestDiffsOfConsecutiveSnapshots(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	f := newFixture(t, d.App)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	v1 := inventoryOf("a@1.0.0", "b@2.0.0", "c@1.0.0", "d@3.0.0")
	v2 := inventoryOf("a@1.1.0", "b@1.9.0", "c@1.0.0", "e@1.0.0") // a monte, b descend, d retiré, e ajouté
	s1 := f.storeAt(t, 1, v1, t0, f.blob)
	s2 := f.storeAt(t, 2, v2, t0.Add(time.Hour), f.blob)
	s3 := f.storeAt(t, 3, v2, t0.Add(2*time.Hour), f.blob) // même inventaire
	if diffJobs(t, f, f.main) != 1 {
		t.Fatalf("job de différences de la référence : %d", diffJobs(t, f, f.main))
	}
	h := newHistory(t, d.App, DefaultRetention(), time.Now())

	// Avant le calcul : la frise signale la différence en attente, la comparaison la
	// calcule.
	page, err := NewService(d.App).Snapshots(ctx, f.org, f.repo, f.main, "", 10)
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("frise : %v, %v", page.Items, err)
	}
	if s := page.Items[1]; s.ID != s2.SnapshotID || !s.ChangesPending || s.Changes != nil || *s.PreviousID != s1.SnapshotID {
		t.Fatalf("instantané 2 avant calcul : %+v", s)
	}
	res, err := h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, To: s2.SnapshotID, Limit: 10})
	if err != nil || res.Stored || res.From.ID != s1.SnapshotID {
		t.Fatalf("comparaison avant calcul : %+v, %v", res, err)
	}
	want := DiffCounts{Added: 1, Removed: 1, Upgraded: 1, Downgraded: 1}
	if res.Counts != want || len(res.Changes.Items) != 4 {
		t.Fatalf("comptes %+v, changements %d", res.Counts, len(res.Changes.Items))
	}

	n, err := h.ComputeMissing(ctx, f.org, f.main)
	if err != nil || n != 1 {
		t.Fatalf("calcul : %d couples, %v (attendu 1 : le couple 2→3 n'a rien à calculer)", n, err)
	}
	if n, err := h.ComputeMissing(ctx, f.org, f.main); err != nil || n != 0 {
		t.Fatalf("second calcul : %d, %v", n, err)
	}
	page, err = NewService(d.App).Snapshots(ctx, f.org, f.repo, f.main, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if c := page.Items[1].Changes; c == nil || *c != want || page.Items[1].ChangesPending {
		t.Fatalf("instantané 2 : %+v", page.Items[1])
	}
	if c := page.Items[0].Changes; c == nil || c.Total() != 0 || page.Items[0].ID != s3.SnapshotID {
		t.Fatalf("instantané 3, même ensemble : %+v", page.Items[0])
	}
	if s := page.Items[2]; s.PreviousID != nil || s.Changes != nil || s.ChangesPending {
		t.Fatalf("premier instantané : %+v", s)
	}

	res, err = h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, To: s2.SnapshotID, Limit: 10})
	if err != nil || !res.Stored || res.Counts != want {
		t.Fatalf("comparaison enregistrée : %+v, %v", res, err)
	}
	var kinds []ChangeKind
	for _, c := range res.Changes.Items {
		kinds = append(kinds, c.Kind)
	}
	if !slices.Equal(kinds, ChangeKinds()) {
		t.Fatalf("ordre des natures : %v", kinds)
	}
	up := res.Changes.Items[2]
	if up.Name != "a" || up.Old.Version != "1.0.0" || up.New.Version != "1.1.0" || up.Old.PURL != "pkg:npm/a@1.0.0" {
		t.Fatalf("montée : %+v %+v %+v", up, up.Old, up.New)
	}

	// Filtre et pagination.
	res, err = h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, To: s2.SnapshotID, Kind: ChangeDowngraded, Limit: 10})
	if err != nil || len(res.Changes.Items) != 1 || res.Changes.Items[0].Name != "b" || res.Counts != want {
		t.Fatalf("filtre : %+v, %v", res.Changes.Items, err)
	}
	var seen []string
	cursor := ""
	for range 5 {
		res, err = h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, To: s2.SnapshotID, Cursor: cursor, Limit: 3})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range res.Changes.Items {
			seen = append(seen, c.PURLBase)
		}
		if cursor = res.Changes.NextCursor; cursor == "" {
			break
		}
	}
	if len(seen) != 4 {
		t.Fatalf("pagination : %v", seen)
	}

	// Couple quelconque, à rebours : calculé à la demande, non enregistré.
	res, err = h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, From: s3.SnapshotID, To: s1.SnapshotID, Limit: 10})
	if err != nil || res.Stored || res.Counts != (DiffCounts{Added: 1, Removed: 1, Upgraded: 1, Downgraded: 1}) {
		t.Fatalf("à rebours : %+v, %v", res.Counts, err)
	}
	if f.count(t, `SELECT count(*) FROM set_diffs`) != 1 {
		t.Fatal("une comparaison à la demande ne s'enregistre pas")
	}
	// Même ensemble : aucune différence.
	if res, err = h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, From: s2.SnapshotID, To: s3.SnapshotID, Limit: 10}); err != nil ||
		res.Counts.Total() != 0 || len(res.Changes.Items) != 0 {
		t.Fatalf("même ensemble : %+v, %v", res, err)
	}

	// Erreurs : premier instantané, instantané d'un autre projet, nature inconnue, borne.
	if _, err := h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, To: s1.SnapshotID, Limit: 10}); !errors.Is(err, ErrNoPrevious) {
		t.Fatalf("sans précédent : %v", err)
	}
	if _, err := h.Diff(ctx, f.org, DiffRequest{ProjectID: f.host, To: s2.SnapshotID, Limit: 10}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("autre projet : %v", err)
	}
	if _, err := h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, To: s2.SnapshotID, Kind: "moved", Limit: 10}); !errors.Is(err, ErrInvalidChangeKind) {
		t.Fatalf("nature inconnue : %v", err)
	}
	if _, err := h.Diff(ctx, f.org, DiffRequest{ProjectID: f.repo, To: s2.SnapshotID, Limit: ChangePageMax + 1}); err == nil {
		t.Fatal("page trop grande acceptée")
	}

	// Isolement : une autre organisation ne voit ni l'instantané ni la différence.
	other := newFixture(t, d.App)
	if _, err := h.Diff(ctx, other.org, DiffRequest{ProjectID: f.repo, To: s2.SnapshotID, Limit: 10}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("autre organisation : %v", err)
	}
	if n := other.count(t, `SELECT count(*) FROM set_diffs`); n != 0 {
		t.Fatalf("autre organisation : %d différences visibles", n)
	}

	choices, err := h.Choices(ctx, f.org, f.repo, 2)
	if err != nil || len(choices) != 2 || choices[0].ID != s3.SnapshotID || choices[1].ID != s2.SnapshotID {
		t.Fatalf("choix : %+v, %v", choices, err)
	}
}

// TestDiffJobHandler : le handler lit sa charge et calcule les couples manquants.
func TestDiffJobHandler(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	f := newFixture(t, d.App)
	t0 := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	f.storeAt(t, 1, inventoryOf("a@1.0.0"), t0, f.blob)
	f.storeAt(t, 2, inventoryOf("a@2.0.0"), t0.Add(time.Hour), f.blob)
	h := newHistory(t, d.App, DefaultRetention(), time.Now())
	payload := []byte(fmt.Sprintf(`{"ref_id":%q}`, f.main))
	if err := h.DiffHandler().Handle(context.Background(), jobs.Execution{Kind: DiffKind, OrgID: f.org, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM set_diff_items WHERE kind = 'upgraded'`) != 1 {
		t.Fatal("différence non enregistrée")
	}
	if err := h.DiffHandler().Handle(context.Background(), jobs.Execution{Kind: DiffKind, Payload: payload}); !jobs.IsPermanent(err) {
		t.Fatalf("sans organisation : %v", err)
	}
}

// retentionScene : une référence de dépôt dont l'historique couvre six mois, avec ses
// réceptions, un constat et une analyse, sous une horloge simulée.
type retentionScene struct {
	f     fixture
	now   time.Time
	snaps map[string]uuid.UUID
	sets  map[string]uuid.UUID
	blobs map[string]uuid.UUID
}

func day(m time.Month, d int) time.Time { return time.Date(2026, m, d, 10, 0, 0, 0, time.UTC) }

func newRetentionScene(t *testing.T, pool *db.Pool) retentionScene {
	t.Helper()
	sc := retentionScene{f: newFixture(t, pool), now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		snaps: map[string]uuid.UUID{}, sets: map[string]uuid.UUID{}, blobs: map[string]uuid.UUID{}}
	// Coupure à 90 jours : 2026-08-03 12:00 UTC.
	steps := []struct {
		name string
		at   time.Time
		inv  string
	}{
		{"s1", day(5, 3), "a@1"},    // mai, supprimé
		{"s2", day(5, 20), "i@1"},   // mai, gardé : dernière analyse ; ensemble partagé avec s9
		{"s3", day(5, 28), "c@1"},   // dernier de mai
		{"s4", day(6, 10), "d@1"},   // seul de juin
		{"s5", day(7, 5), "e@1"},    // juillet, supprimé (constat, réception récente)
		{"s6", day(7, 25), "f@1"},   // dernier de juillet
		{"s7", day(8, 1), "g@1"},    // août avant la coupure, supprimé
		{"s8", day(8, 2), "h@1"},    // dernier avant la coupure : en vigueur au début de la fenêtre
		{"s9", day(9, 15), "i@1"},   // dans la fenêtre
		{"s10", day(10, 30), "j@1"}, // courant
	}
	for i, s := range steps {
		blob := sc.f.newBlob(t)
		res := sc.f.storeAt(t, i+1, inventoryOf(s.inv), s.at, blob)
		sc.snaps[s.name], sc.sets[s.name], sc.blobs[s.name] = res.SnapshotID, res.SetID, blob
	}
	f := sc.f
	f.exec(t, `INSERT INTO ref_analyses (org_id, ref_id, project_id, set_id, snapshot_id, vulndb_archive, vulndb_built, analyzed_at,
		match_count, unmatched_count) VALUES ($1, $2, $3, $4, $5, $6, now(), now(), 0, 0)`,
		f.org, f.main, f.repo, sc.sets["s2"], sc.snaps["s2"], newID())
	// Constat vu pour la dernière fois par s5.
	f.exec(t, `INSERT INTO vulnerabilities (id, source_rank, severity, vulndb_built, updated_at)
		VALUES ('CVE-2026-0001', 0, 'high', now(), now()) ON CONFLICT DO NOTHING`)
	f.exec(t, `INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status, resolution, severity, risk,
		fix_state, match_type, first_seen_at, last_seen_at, resolved_at, snapshot_id, vulndb_archive, vulndb_built, updated_at)
		SELECT $1, $2, $3, $4, c.id, 'CVE-2026-0001', 'resolved', 'component_removed', 'high', 50, 'fixed', 'exact-direct',
		       now(), now(), now(), $5, $6, now(), now() FROM components c WHERE c.purl = 'pkg:npm/e@1'`,
		f.org, newID(), f.repo, f.main, sc.snaps["s5"], newID())
	f.exec(t, `INSERT INTO finding_events (org_id, finding_id, at, kind, snapshot_id, vulndb_archive)
		SELECT org_id, id, now(), 'opened', snapshot_id, vulndb_archive FROM findings`)
	// Réceptions : celle de s5, reçue récemment (envoi en retard) ; une ancienne en échec
	// avec son propre SBOM ; une récente en échec qui réutilise le SBOM de s1.
	ingestion := func(snapshot *uuid.UUID, blob uuid.UUID, received time.Time) {
		status, outcome, errKey := "done", any("created"), any(nil)
		if snapshot == nil {
			status, outcome, errKey = "failed", nil, "error.ingest.schema_invalid"
		}
		f.exec(t, `INSERT INTO ingestions (org_id, id, agent_id, project_id, ref_id, scanned_at, blob_id, status, error_key, snapshot_id,
			outcome, received_at, finished_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $6, $6)`,
			f.org, newID(), f.agent, f.repo, f.main, received, blob, status, errKey, snapshot, outcome)
	}
	s5 := sc.snaps["s5"]
	ingestion(&s5, sc.blobs["s5"], day(10, 20))
	sc.blobs["old-failed"] = f.newBlob(t)
	ingestion(nil, sc.blobs["old-failed"], day(6, 1))
	ingestion(nil, sc.blobs["s1"], day(10, 25))
	return sc
}

func (sc retentionScene) remaining(t *testing.T) []string {
	t.Helper()
	var out []string
	for i := 1; i <= 10; i++ {
		name := fmt.Sprintf("s%d", i)
		if sc.f.count(t, `SELECT count(*) FROM snapshots WHERE id = $1`, sc.snaps[name]) == 1 {
			out = append(out, name)
		}
	}
	return out
}

// TestRetentionKeepsOnePerMonthAndOrphansOnly : critère d'acceptation de T17 — au-delà de
// 90 jours, un instantané par mois (le dernier), l'instantané en vigueur à la coupure,
// celui de la dernière analyse et le courant restent ; les ensembles et SBOM orphelins, et
// eux seuls, sont supprimés ; les différences suivent ; un second passage ne fait rien.
func TestRetentionKeepsOnePerMonthAndOrphansOnly(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	ctx := context.Background()
	sc := newRetentionScene(t, d.App)
	f := sc.f
	other := newRetentionScene(t, d.App) // autre organisation, même historique
	h := newHistory(t, d.App, DefaultRetention(), sc.now)
	if _, err := h.ComputeMissing(ctx, f.org, f.main); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM set_diffs`); n != 9 {
		t.Fatalf("%d différences avant la rétention, attendu 9", n)
	}
	if _, err := f.pool.DB().ExecContext(ctx, `DELETE FROM jobs WHERE kind = $1`, DiffKind); err != nil {
		t.Fatal(err)
	}

	rep, err := h.Retain(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sc.remaining(t), []string{"s2", "s3", "s4", "s6", "s8", "s9", "s10"}; !slices.Equal(got, want) {
		t.Fatalf("instantanés gardés %v, attendu %v", got, want)
	}
	// Ensembles : ceux de s1, s5, s7 supprimés ; celui de s2 reste (partagé avec s9).
	for name, gone := range map[string]bool{"s1": true, "s5": true, "s7": true, "s2": false, "s3": false, "s10": false} {
		if n := f.count(t, `SELECT count(*) FROM component_sets WHERE id = $1`, sc.sets[name]); (n == 0) != gone {
			t.Errorf("ensemble de %s : %d ligne(s), supprimé attendu %v", name, n, gone)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM component_set_items i WHERE NOT EXISTS (SELECT 1 FROM component_sets s WHERE s.id = i.set_id)`); n != 0 {
		t.Fatalf("%d éléments sans ensemble", n)
	}
	// SBOM : ceux de s5, s7 et de l'ancienne réception en échec supprimés ; celui de s1
	// reste (réception récente) ; ceux des instantanés gardés restent.
	for name, gone := range map[string]bool{"s5": true, "s7": true, "old-failed": true, "s1": false, "s2": false, "s8": false} {
		if n := f.count(t, `SELECT count(*) FROM sbom_blobs WHERE id = $1`, sc.blobs[name]); (n == 0) != gone {
			t.Errorf("SBOM de %s : %d ligne(s), supprimé attendu %v", name, n, gone)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM ingestions`); n != 1 {
		t.Fatalf("%d réceptions restantes, attendu 1 (la récente en échec)", n)
	}
	if n := f.count(t, `SELECT count(*) FROM findings WHERE snapshot_id IS NULL`); n != 1 {
		t.Fatalf("le constat vu par s5 doit rester sans instantané (%d)", n)
	}
	if n := f.count(t, `SELECT count(*) FROM finding_events WHERE snapshot_id IS NULL`); n != 1 {
		t.Fatalf("l'historique du constat doit rester sans instantané (%d)", n)
	}
	// Réceptions : celle de s5 et l'ancienne en échec ; SBOM : s5, s7, l'ancienne réception
	// en échec et celui, jamais référencé, de la fixture.
	if rep.Snapshots != 3 || rep.Ingestions != 2 || rep.Sets != 3 || rep.Blobs != 4 || rep.Recompute != 1 {
		t.Fatalf("bilan %+v", rep)
	}
	// Différences : celles qui touchaient un instantané supprimé ont disparu, les couples
	// nouveaux (s4→s6, s6→s8, s2→s3 déjà là…) sont mis en file.
	if diffJobs(t, f, f.main) != 1 {
		t.Fatal("calcul des nouveaux couples non mis en file")
	}
	if n, err := h.ComputeMissing(ctx, f.org, f.main); err != nil || n != 2 {
		t.Fatalf("nouveaux couples : %d, %v (attendu s4→s6 et s6→s8)", n, err)
	}
	if n := f.count(t, `SELECT count(*) FROM set_diffs`); n != 6 {
		t.Fatalf("%d différences après la rétention, attendu 6", n)
	}
	st, ok, err := h.Retention(ctx, f.org)
	if err != nil || !ok || !st.Horizon.Equal(DefaultRetention().Cutoff(sc.now)) || !st.LastRunAt.Equal(sc.now) {
		t.Fatalf("état de la rétention : %+v, %v, %v", st, ok, err)
	}

	// Idempotence : rien de plus au second passage.
	rep, err = h.Retain(ctx, f.org)
	if err != nil || rep != (RetentionReport{}) {
		t.Fatalf("second passage : %+v, %v", rep, err)
	}
	// L'autre organisation n'a pas été touchée.
	if got := other.remaining(t); len(got) != 10 {
		t.Fatalf("autre organisation : %v", got)
	}
}

// TestRetentionPolicyVariants : nombre gardé, sans conservation mensuelle, désactivée.
func TestRetentionPolicyVariants(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	ctx := context.Background()
	cases := []struct {
		name   string
		policy RetentionPolicy
		want   []string
	}{
		// Les 6 plus récents (s5 à s10), puis le dernier de chaque mois.
		{"nombre", RetentionPolicy{Enabled: true, Days: 90, Count: 6, Monthly: true}, []string{"s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10"}},
		// Sans conservation mensuelle : l'instantané en vigueur à la coupure reste.
		{"sans mois", RetentionPolicy{Enabled: true, Days: 90}, []string{"s2", "s8", "s9", "s10"}},
		{"désactivée", RetentionPolicy{Days: 90, Monthly: true}, []string{"s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := newRetentionScene(t, d.App)
			h := newHistory(t, d.App, c.policy, sc.now)
			if _, err := h.Retain(ctx, sc.f.org); err != nil {
				t.Fatal(err)
			}
			if got := sc.remaining(t); !slices.Equal(got, c.want) {
				t.Fatalf("gardés %v, attendu %v", got, c.want)
			}
			if _, ok, _ := h.Retention(ctx, sc.f.org); ok != c.policy.Enabled {
				t.Fatalf("état enregistré : %v", ok)
			}
		})
	}
}

// TestRetentionKeepsRecentlyReceivedAndLastSnapshot : un instantané ancien reçu dans la
// fenêtre (rattrapage) reste ; le seul instantané d'une référence reste, quel que soit
// son âge.
func TestRetentionKeepsRecentlyReceivedAndLastSnapshot(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	ctx := context.Background()
	f := newFixture(t, d.App)
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	old := f.storeAt(t, 1, inventoryOf("a@1"), day(3, 1), f.newBlob(t))
	f.storeAt(t, 2, inventoryOf("a@2"), day(3, 2), f.newBlob(t))
	// Rattrapage : scanné en mars, reçu hier.
	late := f.repoRecord(commit(3), inventoryOf("a@3"), day(3, 3))
	late.BlobID = f.newBlob(t)
	if err := f.pool.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
		_, err := Store(ctx, tx, late, now.Add(-24*time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.storeAt(t, 4, inventoryOf("a@4"), day(10, 1), f.newBlob(t))
	host := f.hostRecord(inventoryOf("h@1"), day(1, 5))
	host.BlobID = f.newBlob(t)
	if err := f.pool.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
		_, err := Store(ctx, tx, host, day(1, 5))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h := newHistory(t, d.App, RetentionPolicy{Enabled: true, Days: 90}, now)
	if _, err := h.Retain(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE ref_id = $1`, f.hostRef); n != 1 {
		t.Fatalf("seul instantané de l'hôte : %d", n)
	}
	// s1 supprimé ; s2 gardé (dernier ancien reçu hors fenêtre), s3 (reçu dans la
	// fenêtre) et s4 (courant) gardés.
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE ref_id = $1`, f.main); n != 3 {
		t.Fatalf("%d instantanés de main, attendu 3", n)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE id = $1`, old.SnapshotID); n != 0 {
		t.Fatal("le plus ancien aurait dû être supprimé")
	}
}

// TestOrphanDeletionSkipsSetLockedByIngestion : un ensemble orphelin qu'une ingestion en
// cours a verrouillé pour le réutiliser (FOR KEY SHARE) n'est pas supprimé.
func TestOrphanDeletionSkipsSetLockedByIngestion(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	ctx := context.Background()
	f := newFixture(t, d.App)
	set := newID()
	f.exec(t, `INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
		VALUES ($1, $2, sha256('orphelin'::bytea), 0, 0, 0, 0)`, f.org, set)
	h := newHistory(t, d.App, DefaultRetention(), time.Now())
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.pool.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
			if _, err := tx.ExecContext(ctx, `SELECT id FROM component_sets WHERE id = $1 FOR KEY SHARE`, set); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	// Sans SKIP LOCKED, la suppression attendrait l'ingestion : le délai le fait voir.
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	n, err := h.deleteOrphans(wait, f.org, orphanSets)
	cancel()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err != nil || n != 0 {
		t.Fatalf("ensemble verrouillé supprimé : %d, %v", n, err)
	}
	if n, err := h.deleteOrphans(ctx, f.org, orphanSets); err != nil || n != 1 {
		t.Fatalf("ensemble libéré : %d, %v", n, err)
	}
}

// TestEnqueueRetentionCoversEveryOrganization : un job par organisation, archivées
// comprises, et la clé d'unicité fond les mises en file répétées.
func TestEnqueueRetentionCoversEveryOrganization(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	ctx := context.Background()
	a, b := newFixture(t, d.App), newFixture(t, d.App)
	b.exec(t, `UPDATE organizations SET archived_at = now()`)
	h := newHistory(t, d.App, DefaultRetention(), time.Now())
	for range 2 {
		if err := h.RetentionAllHandler().Handle(ctx, jobs.Execution{Kind: RetentionAllKind}); err != nil {
			t.Fatal(err)
		}
	}
	for _, org := range []tenant.OrgID{a.org, b.org} {
		var n int
		if err := d.App.DB().QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE kind = $1 AND org_id = $2`, RetentionOrgKind, org.UUID()).
			Scan(&n); err != nil || n != 1 {
			t.Fatalf("organisation %s : %d jobs, %v", org, n, err)
		}
	}
	if err := h.RetentionOrgHandler().Handle(ctx, jobs.Execution{Kind: RetentionOrgKind}); !jobs.IsPermanent(err) {
		t.Fatalf("sans organisation : %v", err)
	}
	if err := h.RetentionOrgHandler().Handle(ctx, jobs.Execution{Kind: RetentionOrgKind, OrgID: a.org}); err != nil {
		t.Fatal(err)
	}
}
