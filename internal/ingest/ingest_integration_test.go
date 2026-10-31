//go:build integration

package ingest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/inventory"
	"leblanc.io/open-go-sbom/internal/jobs"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/sbom"
)

func TestReceiveAndDecodeRepo(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	s := newService(t, tdb.App, testLimits)
	ctx := context.Background()
	data := testdata(t, "portail-client-ia.cdx16.json")

	in, err := s.Receive(ctx, f.org, f.repoAgent, f.repoContext(1), bytes.NewReader(gzipped(t, data)))
	if err != nil || in.Status != StatusQueued || in.Duplicate {
		t.Fatalf("réception %+v, %v", in, err)
	}
	if n := f.count(t, `SELECT count(*) FROM jobs WHERE kind = $1 AND payload->>'ingestion_id' = $2`, DecodeKind, in.ID.String()); n != 1 {
		t.Fatalf("%d jobs de décodage", n)
	}
	// Le handler est idempotent : deux exécutions, un seul instantané.
	for range 2 {
		if err := s.Decode(ctx, f.org, in.ID); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Get(ctx, f.org, f.repoAgent, in.ID)
	if err != nil || got.Status != StatusDone || got.SnapshotID == nil || got.Outcome != string(inventory.OutcomeCreated) ||
		*got.Components != 12 || *got.Skipped != 0 || got.Format != sbom.FormatCycloneDX || got.SpecVersion != "1.6" || got.FinishedAt == nil {
		t.Fatalf("ingestion %+v, %v", got, err)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots`); n != 1 {
		t.Errorf("%d instantanés", n)
	}
	if n := f.count(t, `SELECT count(*) FROM jobs WHERE kind = $1`, inventory.AnalysisKind); n != 1 {
		t.Errorf("%d jobs d'analyse", n)
	}

	// Même SBOM, même référence, même commit (brut cette fois) : rien de nouveau.
	dup, err := s.Receive(ctx, f.org, f.repoAgent, f.repoContext(1), bytes.NewReader(data))
	if err != nil || !dup.Duplicate || dup.ID != in.ID {
		t.Fatalf("doublon %+v, %v", dup, err)
	}
	for table, want := range map[string]int{"ingestions": 1, "sbom_blobs": 1, "snapshots": 1} {
		if n := f.count(t, `SELECT count(*) FROM `+table); n != want {
			t.Errorf("%s : %d lignes, attendu %d", table, n, want)
		}
	}

	// Nouveau commit, même inventaire mais autre document (horodatage) : deux
	// instantanés, un seul ensemble.
	other := bytes.Replace(data, []byte("2026-10-30T09:12:00Z"), []byte("2026-10-31T09:12:00Z"), 1)
	second := receive(t, s, f, f.repoAgent, f.repoContext(2), other)
	if second.Status != StatusDone || *second.SnapshotID == *got.SnapshotID {
		t.Fatalf("second commit %+v", second)
	}
	if n := f.count(t, `SELECT count(*) FROM component_sets`); n != 1 {
		t.Errorf("%d ensembles", n)
	}
	if n := f.count(t, `SELECT count(*) FROM sbom_blobs`); n != 2 {
		t.Errorf("%d blobs", n)
	}

	blob, err := s.Blob(ctx, f.org, f.uuidOf(t, `SELECT blob_id FROM snapshots WHERE id = $1`, *got.SnapshotID))
	if err != nil || !bytes.Equal(blob, data) {
		t.Errorf("blob relu différent du SBOM envoyé (%v)", err)
	}
	recent, err := s.Recent(ctx, f.org, f.repo, 10)
	if err != nil || len(recent) != 2 || recent[0].ID != second.ID {
		t.Errorf("ingestions récentes %v, %v", recent, err)
	}
	if _, err := s.Recent(ctx, f.org, f.repo, RecentPageMax+1); err == nil {
		t.Error("liste non bornée")
	}
}

func TestReceiveHostIdenticalScans(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	s := newService(t, tdb.App, testLimits)
	data := testdata(t, "debian-12.cdx15.json")
	t0 := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Microsecond)
	first := receive(t, s, f, f.hostAgent, f.hostContext(t0), data)
	second := receive(t, s, f, f.hostAgent, f.hostContext(t0.Add(24*time.Hour)), data)
	if first.Status != StatusDone || second.Status != StatusDone || second.Duplicate || second.ID == first.ID {
		t.Fatalf("envois %+v / %+v", first, second)
	}
	if *second.SnapshotID != *first.SnapshotID || second.Outcome != string(inventory.OutcomeUnchanged) {
		t.Fatalf("second envoi : instantané %v, effet %s", *second.SnapshotID, second.Outcome)
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE last_scanned_at = $1`, t0.Add(24*time.Hour)); n != 1 {
		t.Error("date de dernière analyse non mise à jour")
	}
	if n := f.count(t, `SELECT count(*) FROM sbom_blobs`); n != 1 {
		t.Errorf("%d blobs pour deux envois identiques", n)
	}
}

func (f fixture) uuidOf(t testing.TB, query string, args ...any) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), query, args...).Scan(&id)
	})
	if err != nil {
		t.Fatalf("%s : %v", query, err)
	}
	return id
}

// Critère : un agent ne peut pas envoyer pour une référence qui ne lui est pas confiée.
func TestReceiveRefusesForeignRefs(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f, other := newFixture(t, tdb.App), newFixture(t, tdb.App)
	s := newService(t, tdb.App, testLimits)
	ctx := context.Background()
	data := testdata(t, "portail-client.cdx16.json")
	cases := map[string]struct {
		org   fixture
		agent uuid.UUID
		c     Context
	}{
		"projet non confié":  {f, f.repoAgent, func() Context { c := f.repoContext(1); c.ProjectID = f.other; return c }()},
		"branche non suivie": {f, f.repoAgent, func() Context { c := f.repoContext(1); c.RefName = "dev"; return c }()},
		"projet d'un autre agent": {f, f.repoAgent, Context{ProjectID: f.host, RefKind: project.RefHost, RefName: f.hostName,
			ScannedAt: time.Now()}},
		"autre organisation":     {other, other.repoAgent, f.repoContext(1)},
		"agent d'une autre org.": {f, other.repoAgent, f.repoContext(1)},
	}
	for name, tc := range cases {
		if err := s.Authorize(ctx, tc.org.org, tc.agent, tc.c); !errors.Is(err, ErrRefUnknown) {
			t.Errorf("%s : Authorize %v", name, err)
		}
		if _, err := s.Receive(ctx, tc.org.org, tc.agent, tc.c, bytes.NewReader(data)); !errors.Is(err, ErrRefUnknown) {
			t.Errorf("%s : Receive %v", name, err)
		}
	}
	if err := s.Authorize(ctx, f.org, f.repoAgent, f.repoContext(1)); err != nil {
		t.Errorf("référence confiée refusée : %v", err)
	}
	// Une référence retirée n'accepte plus d'envoi.
	f.exec(t, `UPDATE tracked_refs SET removed_at = now() WHERE project_id = $1`, f.repo)
	if err := s.Authorize(ctx, f.org, f.repoAgent, f.repoContext(1)); !errors.Is(err, ErrRefUnknown) {
		t.Errorf("référence retirée : %v", err)
	}
	if v, ok := account.IsValidation(s.Authorize(ctx, f.org, f.repoAgent, Context{})); !ok || v.Key != KeyRefInvalid {
		t.Errorf("contexte vide : %v", v)
	}
	for _, table := range []string{"ingestions", "sbom_blobs"} {
		if n := f.count(t, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s : %d lignes après des refus", table, n)
		}
	}
	// Une ingestion n'est lue que par son agent.
	in := receive(t, s, other, other.repoAgent, other.repoContext(1), data)
	if _, err := s.Get(ctx, other.org, other.repoAgent, in.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, f.org, f.repoAgent, in.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("ingestion d'une autre organisation : %v", err)
	}
	other.exec(t, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', 'second')`, other.org, f.repoAgent)
	if _, err := s.Get(ctx, other.org, f.repoAgent, in.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("ingestion d'un autre agent : %v", err)
	}
	if _, err := s.Blob(ctx, f.org, in.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("blob inconnu : %v", err)
	}
}

// Critère : un SBOM malformé, trop gros, trop profond ou trop riche produit une ingestion
// failed avec une clé d'erreur, sans instantané partiel.
func TestDecodeFailures(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	limits := Limits{MaxUpload: 1 << 20, SBOM: sbom.Limits{MaxBytes: 2 << 20, MaxDepth: 12, MaxComponents: 50}}
	s := newService(t, tdb.App, limits)
	deep := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"x":` + strings.Repeat("[", 20) + strings.Repeat("]", 20) + `}`
	cases := []struct {
		name string
		data []byte
		key  string
	}{
		{"malformé", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{]}`), sbom.KeyMalformed},
		{"XML", []byte(`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>`), sbom.KeyUnsupportedFormat},
		{"CycloneDX 1.4", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), sbom.KeyUnsupportedFormat},
		{"trop profond", []byte(deep), sbom.KeyTooDeep},
		{"trop riche", syntheticCycloneDX(51, "00000000-0000-4000-8000-000000000000"), sbom.KeyTooManyComponents},
		{"hors schéma", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":"un"}`), sbom.KeySchemaInvalid},
		{"trop gros décompressé", gzipped(t, append([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","x":"`),
			bytes.Repeat([]byte("a"), 3<<20)...)), sbom.KeyTooLarge},
		{"gzip corrompu", gzipped(t, []byte(`{"a":1}`))[:15], sbom.KeyMalformed},
	}
	for i, tc := range cases {
		in := receive(t, s, f, f.repoAgent, f.repoContext(i+1), tc.data)
		if in.Status != StatusFailed || in.ErrorKey != tc.key || in.SnapshotID != nil || in.FinishedAt == nil {
			t.Errorf("%s : %+v, attendu la clé %s", tc.name, in, tc.key)
		}
	}
	for _, table := range []string{"snapshots", "components", "component_sets", "ref_current"} {
		if n := f.count(t, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s : %d lignes après des échecs", table, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM ingestions WHERE error_key = $1 AND error_detail LIKE '/%'`, sbom.KeySchemaInvalid); n != 1 {
		t.Error("le détail d'une violation de schéma est son pointeur JSON")
	}
	// Envoi au-delà de la taille reçue : 413 sans ingestion.
	_, err := s.Receive(context.Background(), f.org, f.repoAgent, f.repoContext(99), bytes.NewReader(make([]byte, limits.MaxUpload+1)))
	if !errors.Is(err, ErrUploadTooLarge) {
		t.Errorf("envoi trop gros : %v", err)
	}
	// Un échec terminé n'est plus repris ; un nouvel envoi identique est reçu à nouveau.
	failed := receive(t, s, f, f.repoAgent, f.repoContext(1), cases[0].data)
	if failed.Duplicate || failed.Status != StatusFailed {
		t.Errorf("renvoi d'un SBOM en échec : %+v", failed)
	}
	if err := s.Decode(context.Background(), f.org, failed.ID); err != nil {
		t.Errorf("rejeu d'une ingestion en échec : %v", err)
	}
	if err := s.Decode(context.Background(), f.org, newID()); !jobs.IsPermanent(err) {
		t.Errorf("ingestion inconnue : %v", err)
	}
}

// Bout en bout par la file : réception, job pris par un runner, instantané ; ingestions
// concurrentes de plusieurs références et de deux organisations.
func TestEndToEndThroughRunner(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	a, b := newFixture(t, tdb.App), newFixture(t, tdb.App)
	s := newService(t, tdb.App, testLimits)
	runner := jobs.NewRunner(tdb.App, jobs.RunnerOptions{Concurrency: 4, PollInterval: 20 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := runner.Register(DecodeKind, s.DecodeHandler(), jobs.WithOrgLimit(2), jobs.WithTimeout(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	files := []string{"ubuntu-24.04.cdx17.json", "ubuntu-24.04.spdx23.json", "ubuntu-24.04.syft.json", "portail-client.cdx16.json"}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ids []struct {
		f  fixture
		in Ingestion
	}
	for _, f := range []fixture{a, b} {
		for i, name := range files {
			wg.Add(1)
			go func() {
				defer wg.Done()
				in, err := s.Receive(context.Background(), f.org, f.repoAgent, f.repoContext(i+1), bytes.NewReader(testdata(t, name)))
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				ids = append(ids, struct {
					f  fixture
					in Ingestion
				}{f, in})
				mu.Unlock()
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Receive(context.Background(), f.org, f.hostAgent, f.hostContext(time.Now()), bytes.NewReader(testdata(t, "rhel-8.cdx16.json"))); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(30 * time.Second)
	for _, x := range ids {
		for {
			in, err := s.Get(context.Background(), x.f.org, x.f.repoAgent, x.in.ID)
			if err != nil {
				t.Fatal(err)
			}
			if in.Status == StatusDone {
				break
			}
			if in.Status == StatusFailed || time.Now().After(deadline) {
				t.Fatalf("ingestion %+v", in)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for _, f := range []fixture{a, b} {
		// Les trois formats Ubuntu ne donnent pas forcément le même ensemble (licences),
		// mais chacun est un instantané du dépôt.
		if n := f.count(t, `SELECT count(*) FROM snapshots WHERE project_id = $1`, f.repo); n != len(files) {
			t.Errorf("%d instantanés de dépôt", n)
		}
		if n := f.count(t, `SELECT count(*) FROM components WHERE purl LIKE 'pkg:deb/ubuntu/%'`); n != 24 {
			t.Errorf("%d composants Ubuntu", n)
		}
	}
}

// TestReceiveQuotas (SEC-05) : au-delà du quota d'envois d'une référence sur 24 h, ou du
// volume stocké de l'organisation, l'envoi est refusé (ErrQuota) et rien n'est stocké ;
// un doublon n'est pas compté.
func TestReceiveQuotas(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	data := testdata(t, "portail-client-ia.cdx16.json")

	perRef := testLimits
	perRef.MaxPerRefPerDay = 2
	s := newService(t, tdb.App, perRef)
	for n := 1; n <= 2; n++ {
		if _, err := s.Receive(ctx, f.org, f.repoAgent, f.repoContext(n), bytes.NewReader(data)); err != nil {
			t.Fatalf("envoi %d : %v", n, err)
		}
	}
	if _, err := s.Receive(ctx, f.org, f.repoAgent, f.repoContext(3), bytes.NewReader(data)); !errors.Is(err, ErrQuota) {
		t.Fatalf("troisième envoi en 24 h : %v, attendu ErrQuota", err)
	}
	if dup, err := s.Receive(ctx, f.org, f.repoAgent, f.repoContext(1), bytes.NewReader(data)); err != nil || !dup.Duplicate {
		t.Fatalf("doublon au-delà du quota : %+v, %v", dup, err)
	}
	if n := f.count(t, `SELECT count(*) FROM ingestions`); n != 2 {
		t.Fatalf("%d ingestions, attendu 2", n)
	}
	// La fenêtre est glissante : un envoi vieux de plus de 24 h ne compte plus.
	f.exec(t, `UPDATE ingestions SET received_at = received_at - interval '25 hours' WHERE commit_sha = $1`, commit(1))
	if _, err := s.Receive(ctx, f.org, f.repoAgent, f.repoContext(3), bytes.NewReader(data)); err != nil {
		t.Fatalf("après la fenêtre : %v", err)
	}

	// Volume de l'organisation : le blob de l'envoi refusé n'est pas gardé.
	g := newFixture(t, tdb.App)
	storage := testLimits
	storage.MaxOrgStorage = 1
	s = newService(t, tdb.App, storage)
	if _, err := s.Receive(ctx, g.org, g.repoAgent, g.repoContext(1), bytes.NewReader(data)); !errors.Is(err, ErrQuota) {
		t.Fatalf("au-delà du volume stocké : %v, attendu ErrQuota", err)
	}
	if n := g.count(t, `SELECT count(*) FROM sbom_blobs`) + g.count(t, `SELECT count(*) FROM ingestions`); n != 0 {
		t.Fatalf("%d lignes stockées malgré le refus", n)
	}
}

// Mesure : ingestion de 5 000 composants, de la réception à l'instantané (critère de T05).
func TestIngestFiveThousandComponents(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	s := newService(t, tdb.App, testLimits)
	data := syntheticCycloneDX(5000, "11111111-2222-4333-8444-555555555555")
	gz := gzipped(t, data)
	start := time.Now()
	in, err := s.Receive(context.Background(), f.org, f.repoAgent, f.repoContext(1), bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	received := time.Since(start)
	start = time.Now()
	if err := s.Decode(context.Background(), f.org, in.ID); err != nil {
		t.Fatal(err)
	}
	decoded := time.Since(start)
	got, err := s.Get(context.Background(), f.org, f.repoAgent, in.ID)
	if err != nil || got.Status != StatusDone || *got.Components != 5000 {
		t.Fatalf("%+v, %v", got, err)
	}
	t.Logf("5 000 composants (%d Kio JSON, %d Kio gzip) : réception %s, décodage et rangement %s",
		len(data)>>10, len(gz)>>10, received, decoded)
}
