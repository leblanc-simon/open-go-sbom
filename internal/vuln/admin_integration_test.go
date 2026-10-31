//go:build integration

package vuln_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/vulntest"
)

var admin = audit.Actor{UserID: 0, Email: "admin@example.org"}

func uploadOpts() vuln.UploadOptions {
	return vuln.UploadOptions{MaxSize: 1 << 20, ChunkSize: 64, StaleAfter: time.Hour, FileName: "vulnerability-db.tar.zst", Actor: admin}
}

// importJob renvoie l'exécution du job vulndb.import en file pour imp.
func (e env) importJob(t *testing.T, imp vuln.Import, attempt int) jobs.Execution {
	t.Helper()
	var x jobs.Execution
	err := e.pool.DB().QueryRowContext(context.Background(), `SELECT id, payload, max_attempts FROM jobs
		WHERE kind = $1 AND unique_key = $2 AND status = 'pending'`, vuln.ImportKind, "vulndb_import:"+imp.ID.String()).
		Scan(&x.ID, &x.Payload, &x.MaxAttempts)
	if err != nil {
		t.Fatalf("job d'import : %v", err)
	}
	x.Kind, x.Attempt = vuln.ImportKind, attempt
	return x
}

// TestUploadAndImportJob : téléversement par blocs, job mis en file avec la demande
// journalisée, installation par le job (sur une autre instance : autre répertoire),
// blocs supprimés, idempotence.
func TestUploadAndImportJob(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	body := content(t, built1, log4shell())
	imp, err := vuln.Upload(ctx, e.pool, bytes.NewReader(body), uploadOpts())
	if err != nil {
		t.Fatal(err)
	}
	if imp.Status != vuln.ImportQueued || imp.Size != int64(len(body)) || imp.SHA256 != vulntest.SHA256(body) ||
		imp.Chunks != (len(body)+63)/64 || imp.RequestedBy != admin.Email || imp.FileName != "vulnerability-db.tar.zst" {
		t.Fatalf("import %+v", imp)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_import_chunks WHERE import_id = $1`, imp.ID); n != imp.Chunks {
		t.Fatalf("%d blocs", n)
	}
	if n := e.count(t, `SELECT count(*) FROM instance_audit_events WHERE action = 'vulndb.import_requested' AND target_id = $1`, imp.ID.String()); n != 1 {
		t.Fatal("demande d'import non journalisée")
	}
	if _, err := vuln.Upload(ctx, e.pool, bytes.NewReader(body), uploadOpts()); !errors.Is(err, vuln.ErrImportInProgress) {
		t.Fatalf("second import simultané : %v", err)
	}
	x := e.importJob(t, imp, 1)
	if x.MaxAttempts != 3 {
		t.Fatalf("tentatives : %d", x.MaxAttempts)
	}
	worker := vuln.NewChecker(vuln.CheckerOptions{Pool: e.pool, Source: e.source, Engine: e.engine, Dir: t.TempDir(), MaxArchive: 1 << 20})
	if err := worker.ImportHandler().Handle(ctx, x); err != nil {
		t.Fatal(err)
	}
	got, err := vuln.GetImport(ctx, e.pool.DB(), imp.ID)
	if err != nil || got.Status != vuln.ImportDone || got.ArchiveID == nil || got.FinishedAt == nil {
		t.Fatalf("import terminé : %+v, %v", got, err)
	}
	st, err := vuln.ReadState(ctx, e.pool.DB())
	if err != nil || st.Target == nil || st.Target.ID != *got.ArchiveID || st.Target.Origin != vuln.OriginImport {
		t.Fatalf("cible : %+v, %v", st.Target, err)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_import_chunks`); n != 0 {
		t.Fatalf("%d blocs restés après l'import", n)
	}
	if n := e.count(t, `SELECT count(*) FROM instance_audit_events WHERE action = 'vulndb.imported'`); n != 1 {
		t.Fatal("import non journalisé")
	}
	// Rejoué (au moins une fois) : rien ne change.
	if err := worker.ImportHandler().Handle(ctx, x); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_archives`); n != 1 {
		t.Fatalf("%d archives après rejeu", n)
	}
	list, err := vuln.ListImports(ctx, e.pool.DB(), 5)
	if err != nil || len(list) != 1 || list[0].ID != imp.ID {
		t.Fatalf("liste : %+v, %v", list, err)
	}
	// Le même fichier importé de nouveau redevient la cible sans nouvelle archive.
	again, err := vuln.Upload(ctx, e.pool, bytes.NewReader(body), uploadOpts())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ImportHandler().Handle(ctx, e.importJob(t, again, 1)); err != nil {
		t.Fatal(err)
	}
	if got, _ := vuln.GetImport(ctx, e.pool.DB(), again.ID); got.Status != vuln.ImportDone || *got.ArchiveID != st.Target.ID {
		t.Fatalf("réimport : %+v", got)
	}
}

// TestUploadRejections : fichier vide, trop gros, lecture interrompue ; rien ne reste en
// base et un nouvel import reste possible.
func TestUploadRejections(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := vuln.Upload(ctx, e.pool, bytes.NewReader(nil), uploadOpts()); !errors.Is(err, vuln.ErrInvalidArchive) {
		t.Fatalf("vide : %v", err)
	}
	o := uploadOpts()
	o.MaxSize = 100
	if _, err := vuln.Upload(ctx, e.pool, bytes.NewReader(make([]byte, 101)), o); !errors.Is(err, vuln.ErrTooLarge) {
		t.Fatalf("trop gros : %v", err)
	}
	broken := io.MultiReader(bytes.NewReader(make([]byte, 200)), iotest.ErrReader(errors.New("client parti")))
	if _, err := vuln.Upload(ctx, e.pool, broken, uploadOpts()); err == nil || !strings.Contains(err.Error(), "client parti") {
		t.Fatalf("lecture interrompue : %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_imports`) + e.count(t, `SELECT count(*) FROM vulndb_import_chunks`); n != 0 {
		t.Fatalf("%d lignes restées", n)
	}
	if n := e.count(t, `SELECT count(*) FROM jobs`); n != 0 {
		t.Fatalf("%d jobs en file", n)
	}
}

// TestStuckImportsAreAbandoned : un téléversement interrompu (processus tué) ou un import
// dont le job a disparu ne bloquent pas les suivants.
func TestStuckImportsAreAbandoned(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	body := content(t, built1)
	stuck := uuid.New()
	if _, err := e.pool.DB().ExecContext(ctx, `INSERT INTO vulndb_imports (id, status, created_at, updated_at)
		VALUES ($1, 'uploading', now() - interval '2 hours', now() - interval '2 hours')`, stuck); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.DB().ExecContext(ctx, `INSERT INTO vulndb_import_chunks (import_id, seq, data) VALUES ($1, 0, 'x')`, stuck); err != nil {
		t.Fatal(err)
	}
	imp, err := vuln.Upload(ctx, e.pool, bytes.NewReader(body), uploadOpts())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := vuln.GetImport(ctx, e.pool.DB(), stuck); got.Status != vuln.ImportFailed || got.Error == "" {
		t.Fatalf("téléversement interrompu : %+v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_import_chunks WHERE import_id = $1`, stuck); n != 0 {
		t.Fatal("blocs du téléversement interrompu gardés")
	}
	// Job abandonné depuis l'écran des traitements : l'import ne bloque plus.
	if _, err := e.pool.DB().ExecContext(ctx, `DELETE FROM jobs WHERE kind = $1`, vuln.ImportKind); err != nil {
		t.Fatal(err)
	}
	if _, err := vuln.Upload(ctx, e.pool, bytes.NewReader(body), uploadOpts()); err != nil {
		t.Fatalf("import après job disparu : %v", err)
	}
	if got, _ := vuln.GetImport(ctx, e.pool.DB(), imp.ID); got.Status != vuln.ImportFailed {
		t.Fatalf("import sans job : %+v", got)
	}
	// Un téléversement récent, lui, bloque.
	if _, err := e.pool.DB().ExecContext(ctx, `UPDATE vulndb_imports SET status = 'failed', error = 'x', finished_at = now() WHERE status = 'queued'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.DB().ExecContext(ctx, `INSERT INTO vulndb_imports (id, status, created_at, updated_at)
		VALUES ($1, 'uploading', now(), now())`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := vuln.Upload(ctx, e.pool, bytes.NewReader(body), uploadOpts()); !errors.Is(err, vuln.ErrImportInProgress) {
		t.Fatalf("téléversement récent : %v", err)
	}
}

// TestImportJobFailures : une archive invalide est refusée dès la première tentative ; une
// autre erreur est réessayée, puis termine l'import à la dernière tentative.
func TestImportJobFailures(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	imp, err := vuln.Upload(ctx, e.pool, strings.NewReader("pas une archive"), uploadOpts())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.checker.ImportHandler().Handle(ctx, e.importJob(t, imp, 1)); err != nil {
		t.Fatalf("archive invalide : %v (aucun nouvel essai attendu)", err)
	}
	got, _ := vuln.GetImport(ctx, e.pool.DB(), imp.ID)
	if got.Status != vuln.ImportFailed || !strings.Contains(got.Error, "invalide") {
		t.Fatalf("archive invalide : %+v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM instance_audit_events WHERE action = 'vulndb.import_failed'`); n != 1 {
		t.Fatal("refus non journalisé")
	}
	if st, _ := vuln.ReadState(ctx, e.pool.DB()); st.Target != nil {
		t.Fatal("archive invalide devenue la cible")
	}

	// Répertoire local inutilisable : erreur passagère, réessayée.
	imp, err = vuln.Upload(ctx, e.pool, bytes.NewReader(content(t, built1)), uploadOpts())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "fichier")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	broken := vuln.NewChecker(vuln.CheckerOptions{Pool: e.pool, Source: e.source, Engine: e.engine, Dir: filepath.Join(file, "dir"),
		MaxArchive: 1 << 20})
	x := e.importJob(t, imp, 1)
	if err := broken.ImportHandler().Handle(ctx, x); err == nil {
		t.Fatal("erreur passagère non renvoyée")
	}
	if got, _ := vuln.GetImport(ctx, e.pool.DB(), imp.ID); got.Status != vuln.ImportQueued {
		t.Fatalf("après une erreur passagère : %+v", got)
	}
	x.Attempt = x.MaxAttempts
	if err := broken.ImportHandler().Handle(ctx, x); err != nil {
		t.Fatalf("dernière tentative : %v", err)
	}
	if got, _ := vuln.GetImport(ctx, e.pool.DB(), imp.ID); got.Status != vuln.ImportFailed {
		t.Fatalf("après la dernière tentative : %+v", got)
	}
	// Charge illisible : erreur permanente.
	bad := jobs.Execution{Kind: vuln.ImportKind, Payload: json.RawMessage(`{"x":1}`), Attempt: 1, MaxAttempts: 3}
	if err := e.checker.ImportHandler().Handle(ctx, bad); !jobs.IsPermanent(err) {
		t.Fatalf("charge illisible : %v", err)
	}
	// Import inconnu : rien à faire.
	gone := jobs.Execution{Kind: vuln.ImportKind, Payload: json.RawMessage(`{"import_id":"` + uuid.NewString() + `"}`), Attempt: 1, MaxAttempts: 3}
	if err := e.checker.ImportHandler().Handle(ctx, gone); err != nil {
		t.Fatalf("import inconnu : %v", err)
	}
}

// TestPurgeKeepsTarget : la purge supprime toutes les archives sauf la cible, et se
// journalise.
func TestPurgeKeepsTarget(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if p, err := vuln.PurgeArchives(ctx, e.pool, admin); err != nil || p.Archives != 0 {
		t.Fatalf("purge à vide : %+v, %v", p, err)
	}
	var sizes int64
	for i, built := range []time.Time{built1, built1.Add(24 * time.Hour), built1.Add(48 * time.Hour)} {
		body := content(t, built, log4shell())
		e.source.Publish(body, built, "")
		if _, err := e.checker.Check(ctx); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			sizes += int64(len(body))
		}
	}
	p, err := vuln.PurgeArchives(ctx, e.pool, admin)
	if err != nil || p.Archives != 2 || p.Bytes != sizes {
		t.Fatalf("purge : %+v, %v (attendu 2 archives, %d octets)", p, err, sizes)
	}
	st, err := vuln.ReadState(ctx, e.pool.DB())
	if err != nil || st.Target == nil || !st.Target.Built.Equal(built1.Add(48*time.Hour)) {
		t.Fatalf("cible après purge : %+v, %v", st.Target, err)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_archives`); n != 1 {
		t.Fatalf("%d archives", n)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_archive_chunks WHERE archive_id <> $1`, st.Target.ID); n != 0 {
		t.Fatalf("%d blocs d'archives purgées", n)
	}
	if n := e.count(t, `SELECT count(*) FROM instance_audit_events WHERE action = 'vulndb.archives_purged' AND details->>'archives' = '2'`); n != 1 {
		t.Fatal("purge non journalisée")
	}
	// La cible reste synchronisable.
	if _, err := e.manager(t.TempDir()).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestInstancesReportLoadedVersion : chaque instance worker rapporte la base chargée à
// chaque synchronisation et se retire à l'arrêt ; une ligne trop ancienne disparaît.
func TestInstancesReportLoadedVersion(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.pool.DB().ExecContext(ctx, `INSERT INTO vulndb_instances (instance, seen_at) VALUES ('disparue', now() - interval '8 days')`); err != nil {
		t.Fatal(err)
	}
	m := vuln.NewManager(vuln.ManagerOptions{Pool: e.pool, Engine: e.engine, Dir: t.TempDir(), SyncInterval: 10 * time.Millisecond,
		Instance: "worker-1"})
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error)
	go func() { done <- m.Run(runCtx) }()
	waitInstance := func(what string, ok func([]vuln.Instance) bool) []vuln.Instance {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			list, err := vuln.ListInstances(ctx, e.pool.DB())
			if err != nil {
				t.Fatal(err)
			}
			if ok(list) {
				return list
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s : %+v", what, list)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitInstance("instance sans base", func(l []vuln.Instance) bool {
		return len(l) == 1 && l[0].Name == "worker-1" && l[0].Loaded.IsZero() && l[0].SyncError == ""
	})
	e.source.Publish(content(t, built1), built1, "")
	a, err := e.checker.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list := waitInstance("base chargée", func(l []vuln.Instance) bool {
		return len(l) == 1 && l[0].Loaded.ArchiveID == a.ID
	})
	if !list[0].Loaded.Built.Equal(built1) || list[0].Loaded.Schema != a.Schema || list[0].LoadedAt == nil {
		t.Fatalf("instance %+v", list[0])
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM vulndb_instances`); n != 0 {
		t.Fatalf("%d instances après l'arrêt", n)
	}
}
