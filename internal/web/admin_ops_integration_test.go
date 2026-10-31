//go:build integration

package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/jobs"
	"leblanc.io/open-go-sbom/internal/vuln"
	"leblanc.io/open-go-sbom/internal/vuln/vulntest"
	"leblanc.io/open-go-sbom/internal/web/webtest"
)

// deadJob met en file un job puis le passe mort.
func (a *app) deadJob(kind, org string) uuid.UUID {
	a.t.Helper()
	ctx := context.Background()
	id := uuid.New()
	var orgID any
	if org != "" {
		orgID = org
	}
	if _, err := a.tdb.App.DB().ExecContext(ctx, `INSERT INTO jobs (id, kind, org_id, status, attempts, max_attempts, run_at,
		unique_key, last_error, created_at, updated_at, finished_at)
		VALUES ($1, $2, $3, 'dead', 10, 10, now(), $4, 'échec <b>répété</b>', now(), now(), now())`,
		id, kind, orgID, "clé:"+id.String()); err != nil {
		a.t.Fatal(err)
	}
	return id
}

func (a *app) jobStatus(id uuid.UUID) string {
	a.t.Helper()
	var s string
	err := a.tdb.App.DB().QueryRowContext(context.Background(), `SELECT status FROM jobs WHERE id = $1`, id).Scan(&s)
	if err != nil {
		return "absent"
	}
	return s
}

func (a *app) countRows(query string, args ...any) int {
	a.t.Helper()
	var n int
	if err := a.tdb.App.DB().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		a.t.Fatalf("%s : %v", query, err)
	}
	return n
}

// TestFailedJobsScreen : liste des traitements en échec (avec leur organisation), relance
// et abandon journalisés, double envoi, CSRF.
func TestFailedJobsScreen(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	o := a.org("atelier", admin)
	b := a.signIn(admin)
	if p := b.get("/admin/jobs"); p.status != http.StatusOK || !strings.Contains(unescape(p.body), "Aucun traitement en échec") {
		t.Fatalf("écran vide : %d", p.status)
	}
	orgJob := a.deadJob("ingest.decode", o.ID.String())
	instJob := a.deadJob("vulndb.check", "")
	for _, lang := range []string{"fr", "en"} {
		p := b.get("/admin/jobs?lang=" + lang)
		if p.status != http.StatusOK {
			t.Fatalf("%s : %d", lang, p.status)
		}
		webtest.AssertAccessible(t, []byte(p.body))
		webtest.AssertNoInlineCode(t, []byte(p.body))
		if !strings.Contains(p.body, "ingest.decode") || !strings.Contains(p.body, "vulndb.check") ||
			!strings.Contains(p.body, "Org atelier") || strings.Contains(p.body, "<b>répété") {
			t.Errorf("%s : liste incomplète ou erreur non échappée", lang)
		}
	}
	if p := b.post("/admin/jobs/"+orgJob.String()+"/retry", nil); p.status != http.StatusSeeOther || p.location != "/admin/jobs?done=job_retried" {
		t.Fatalf("relance : %d %s", p.status, p.location)
	}
	if s := a.jobStatus(orgJob); s != "pending" {
		t.Fatalf("après relance : %s", s)
	}
	if p := b.post("/admin/jobs/"+orgJob.String()+"/retry", nil); p.status != http.StatusNotFound ||
		!strings.Contains(unescape(p.body), "n'est plus en échec") {
		t.Fatalf("double relance : %d", p.status)
	}
	if p := b.post("/admin/jobs/"+instJob.String()+"/discard", nil); p.status != http.StatusSeeOther {
		t.Fatalf("abandon : %d", p.status)
	}
	if s := a.jobStatus(instJob); s != "absent" {
		t.Fatalf("après abandon : %s", s)
	}
	for _, path := range []string{"/admin/jobs/pas-un-uuid/retry", "/admin/jobs/" + uuid.NewString() + "/inconnue"} {
		if p := b.post(path, nil); p.status != http.StatusNotFound {
			t.Errorf("%s : %d", path, p.status)
		}
	}
	// Sans jeton CSRF : refusé, rien ne change.
	other := a.deadJob("analysis.ref", o.ID.String())
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/admin/jobs/"+other.String()+"/discard", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p := b.do(req); p.status != http.StatusForbidden || a.jobStatus(other) != "dead" {
		t.Fatalf("sans CSRF : %d, %s", p.status, a.jobStatus(other))
	}
	journal := unescape(b.get("/admin/audit").body)
	if !strings.Contains(journal, "Traitement ingest.decode relancé") || !strings.Contains(journal, "Traitement vulndb.check abandonné") {
		t.Error("actions non journalisées")
	}
}

type uploadPart struct{ name, file, value string }

// multipartBody construit un formulaire multipart dans l'ordre des parties.
func multipartBody(t *testing.T, parts ...uploadPart) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		var err error
		if p.file != "" {
			fw, ferr := w.CreateFormFile(p.name, p.file)
			if ferr == nil {
				_, err = fw.Write([]byte(p.value))
			} else {
				err = ferr
			}
		} else {
			err = w.WriteField(p.name, p.value)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func (b *browser) upload(parts ...uploadPart) page {
	b.t.Helper()
	body, ctype := multipartBody(b.t, parts...)
	req, err := http.NewRequest(http.MethodPost, b.app.srv.URL+"/admin/vulndb/import", body)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", ctype)
	return b.do(req)
}

func (b *browser) csrf() string {
	if b.cookie("csrf_token") == "" {
		b.get("/login")
	}
	return b.cookie("csrf_token")
}

// TestVulnDBImportScreen : téléversement en flux réservé aux administrateurs, jeton CSRF en
// tête exigé, borne de taille, un seul import à la fois, installation par le job, état
// affiché.
func TestVulnDBImportScreen(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	u := a.user("user@example.org", false)
	a.org("atelier", admin)
	b := a.signIn(admin)
	archive := string(vulntest.Archive(t, vulntest.Content{Built: time.Now().Add(-150 * time.Minute)}))
	file := uploadPart{name: "archive", file: "vulnerability-db_v6.tar.zst", value: archive}

	// Refus : jeton faux, jeton après le fichier, sans fichier, compte ordinaire, trop gros.
	if p := b.upload(uploadPart{name: "csrf_token", value: "faux"}, file); p.status != http.StatusForbidden {
		t.Errorf("jeton faux : %d", p.status)
	}
	if p := b.upload(file, uploadPart{name: "csrf_token", value: b.csrf()}); p.status != http.StatusForbidden {
		t.Errorf("jeton après le fichier : %d", p.status)
	}
	if p := b.upload(uploadPart{name: "csrf_token", value: b.csrf()}); p.status != http.StatusBadRequest {
		t.Errorf("sans fichier : %d", p.status)
	}
	plain := a.signIn(u)
	if p := plain.upload(uploadPart{name: "csrf_token", value: plain.csrf()}, file); p.status != http.StatusNotFound {
		t.Errorf("compte ordinaire : %d", p.status)
	}
	big := uploadPart{name: "archive", file: "gros.tar.zst", value: strings.Repeat("x", 1<<20+1)}
	if p := b.upload(uploadPart{name: "csrf_token", value: b.csrf()}, big); p.status != http.StatusRequestEntityTooLarge {
		t.Errorf("trop gros : %d", p.status)
	}
	if n := a.countRows(`SELECT count(*) FROM vulndb_imports`); n != 0 {
		t.Fatalf("%d imports après les refus", n)
	}

	p := b.upload(uploadPart{name: "csrf_token", value: b.csrf()}, file)
	if p.status != http.StatusSeeOther || p.location != "/admin/vulndb?done=vulndb_import_queued" {
		t.Fatalf("import : %d %s %s", p.status, p.location, p.body)
	}
	if n := a.countRows(`SELECT count(*) FROM jobs WHERE kind = $1 AND status = 'pending'`, vuln.ImportKind); n != 1 {
		t.Fatalf("%d jobs d'import", n)
	}
	screen := unescape(b.get("/admin/vulndb").body)
	if !strings.Contains(screen, "En attente d'installation") || !strings.Contains(screen, "vulnerability-db_v6.tar.zst") ||
		!strings.Contains(screen, "Un import est en cours") || strings.Contains(screen, `enctype="multipart/form-data"`) {
		t.Error("import en cours non affiché")
	}
	if p := b.upload(uploadPart{name: "csrf_token", value: b.csrf()}, file); p.status != http.StatusConflict {
		t.Errorf("second import : %d", p.status)
	}

	// Le job, sur une instance worker.
	checker := vuln.NewChecker(vuln.CheckerOptions{Pool: a.tdb.App, Source: &vulntest.Source{}, Engine: &vulntest.Engine{},
		Dir: t.TempDir(), MaxArchive: 1 << 20})
	var x jobs.Execution
	if err := a.tdb.App.DB().QueryRowContext(context.Background(), `SELECT id, payload, max_attempts FROM jobs WHERE kind = $1`,
		vuln.ImportKind).Scan(&x.ID, &x.Payload, &x.MaxAttempts); err != nil {
		t.Fatal(err)
	}
	x.Kind, x.Attempt = vuln.ImportKind, 1
	if err := checker.ImportHandler().Handle(context.Background(), x); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"fr", "en"} {
		pg := b.get("/admin/vulndb?lang=" + lang)
		webtest.AssertAccessible(t, []byte(pg.body))
		webtest.AssertNoInlineCode(t, []byte(pg.body))
	}
	screen = unescape(b.get("/admin/vulndb").body)
	if !strings.Contains(screen, "Importée") || !strings.Contains(screen, "admin@example.org") ||
		!strings.Contains(screen, `enctype="multipart/form-data"`) || !strings.Contains(screen, "2 heures") {
		t.Error("import terminé non affiché")
	}
	journal := unescape(b.get("/admin/audit").body)
	if !strings.Contains(journal, "Import de la base de vulnérabilités demandé") || !strings.Contains(journal, "Base de vulnérabilités importée") {
		t.Error("import non journalisé")
	}
}

// TestVulnDBPurgeAndInstances : purge confirmée des archives non cibles ; état de chaque
// instance worker.
func TestVulnDBPurgeAndInstances(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	a.org("atelier", admin)
	b := a.signIn(admin)
	s := a.analysis()
	s.publish(t, time.Now().Add(-3*24*time.Hour-time.Hour))
	old, err := vuln.ReadState(context.Background(), a.tdb.App.DB())
	if err != nil {
		t.Fatal(err)
	}
	s.publish(t, time.Now().Add(-330*time.Minute))
	ctx := context.Background()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO vulndb_instances (instance, archive_id, built_at, schema, loaded_at, seen_at)
			VALUES ('worker-a:1', $1, $2, 'v6.1.10', now(), now())`, []any{old.Target.ID, old.Target.Built}},
		{`INSERT INTO vulndb_instances (instance, seen_at, sync_error) VALUES ('worker-b:2', now() - interval '1 hour', 'disque plein')`, nil},
	} {
		if _, err := a.tdb.App.DB().ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	screen := unescape(b.get("/admin/vulndb").body)
	for _, want := range []string{"worker-a:1", "En retard sur la cible", "3 jours", "worker-b:2", "Sans nouvelles", "disque plein",
		"5 heures", "Purger les archives précédentes"} {
		if !strings.Contains(screen, want) {
			t.Errorf("écran : %q absent", want)
		}
	}
	if p := b.post("/admin/vulndb/purge", nil); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("purge sans confirmation : %d", p.status)
	}
	if n := a.countRows(`SELECT count(*) FROM vulndb_archives`); n != 2 {
		t.Fatalf("%d archives", n)
	}
	if p := b.post("/admin/vulndb/purge", url.Values{"confirm": {"on"}}); p.status != http.StatusSeeOther {
		t.Fatalf("purge : %d", p.status)
	}
	if n := a.countRows(`SELECT count(*) FROM vulndb_archives`); n != 1 {
		t.Fatalf("%d archives après purge", n)
	}
	screen = unescape(b.get("/admin/vulndb?done=vulndb_purged").body)
	if strings.Contains(screen, "Purger les archives précédentes") || !strings.Contains(screen, "Les archives qui ne sont pas la cible sont supprimées") {
		t.Error("écran après purge")
	}
	if !strings.Contains(unescape(b.get("/admin/audit").body), "Archives de la base de vulnérabilités purgées : 1") {
		t.Error("purge non journalisée")
	}
}
