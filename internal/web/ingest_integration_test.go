//go:build integration

package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

func sbomFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../testdata/sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// part est une partie d'un envoi multipart.
type part struct {
	name, contentType string
	body              []byte
}

// upload envoie un corps multipart à POST /api/v1/agent/ingestions.
func (a *app) upload(token string, parts []part, headers ...string) apiResponse {
	a.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		disp := `form-data; name="` + p.name + `"`
		if p.name == "sbom" {
			disp += `; filename="sbom.json"`
		}
		h.Set("Content-Disposition", disp)
		h.Set("Content-Type", p.contentType)
		w, err := mw.CreatePart(h)
		if err != nil {
			a.t.Fatal(err)
		}
		if _, err := w.Write(p.body); err != nil {
			a.t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		a.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, a.srv.URL+"/api/v1/agent/ingestions", &body)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return apiResponse{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

func contextPart(t *testing.T, v any) part {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return part{name: "context", contentType: "application/json", body: raw}
}

type ingestionJSON struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	SnapshotID string `json:"snapshot_id"`
	Outcome    string `json:"outcome"`
	Components int    `json:"component_count"`
	Error      *struct {
		Key, Title, Detail, Pointer string
	} `json:"error"`
}

func decodeIngestion(t *testing.T, r apiResponse) ingestionJSON {
	t.Helper()
	var in ingestionJSON
	if err := json.Unmarshal([]byte(r.body), &in); err != nil {
		t.Fatalf("%d : %s", r.status, r.body)
	}
	return in
}

type repoFixture struct {
	token   string
	p       project.Project
	org     org.Organization
	agentID uuid.UUID
}

// repoSetup crée une organisation, un agent dépôt et un dépôt (branche main) qui lui est
// confié.
func repoSetup(t *testing.T, a *app, slug string, admin user) repoFixture {
	t.Helper()
	ctx := context.Background()
	o := a.org(slug, admin)
	ag, tok, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.projects.Create(ctx, audit.System, o.ID, project.Input{Kind: project.KindRepo, Name: "Portail client", Branches: []string{"main"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.projects.AssignAgent(ctx, audit.System, o.ID, p.Slug, &ag.ID); err != nil {
		t.Fatal(err)
	}
	return repoFixture{token: tok.Plaintext, p: p, org: o, agentID: ag.ID}
}

func repoContext(p project.Project, commit int) map[string]any {
	return map[string]any{"project_id": p.ID, "ref": map[string]string{"kind": "branch", "name": "main"},
		"commit": fmt.Sprintf("%040x", commit), "agent_version": "1.0.0", "scanned_at": time.Now().Add(-time.Hour + time.Duration(commit)*time.Minute)}
}

// Bout en bout par l'API : envoi, décodage, état, doublon, commit du dernier instantané.
func TestIngestionAPIEndToEnd(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	token, p, org := f.token, f.p, f.org.ID
	ctx := context.Background()
	data := sbomFile(t, "portail-client-ia.cdx16.json")

	r := a.upload(token, []part{contextPart(t, repoContext(p, 1)), {name: "sbom", contentType: "application/gzip", body: gzipBytes(t, data)}})
	if r.status != http.StatusAccepted {
		t.Fatalf("envoi : %d %s", r.status, r.body)
	}
	in := decodeIngestion(t, r)
	if in.Status != "queued" {
		t.Fatalf("état %+v", in)
	}
	id := uuid.MustParse(in.ID)
	if err := a.ingest.Decode(ctx, org, id); err != nil {
		t.Fatal(err)
	}
	got := a.api(http.MethodGet, "/api/v1/agent/ingestions/"+in.ID, token, nil)
	if got.status != http.StatusOK {
		t.Fatalf("état : %d %s", got.status, got.body)
	}
	done := decodeIngestion(t, got)
	if done.Status != "done" || done.SnapshotID == "" || done.Outcome != "created" || done.Components != 12 {
		t.Fatalf("ingestion %+v", done)
	}
	// Envoi identique : 200, même ingestion.
	dup := a.upload(token, []part{contextPart(t, repoContext(p, 1)), {name: "sbom", contentType: "application/json", body: data}})
	if dup.status != http.StatusOK || decodeIngestion(t, dup).ID != in.ID {
		t.Fatalf("doublon : %d %s", dup.status, dup.body)
	}
	// Le commit du dernier instantané apparaît dans les projets de l'agent.
	pr := a.api(http.MethodGet, "/api/v1/agent/projects", token, nil)
	if pr.status != http.StatusOK || !strings.Contains(pr.body, `"commit":"`+fmt.Sprintf("%040x", 1)+`"`) || !strings.Contains(pr.body, done.SnapshotID) {
		t.Fatalf("projets : %d %s", pr.status, pr.body)
	}
}

func TestIngestionAPIErrors(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	f, g := repoSetup(t, a, "org-a", admin), repoSetup(t, a, "org-b", a.user("b@example.org", false))
	token, p, org := f.token, f.p, f.org.ID
	otherToken, other := g.token, g.p
	_, enr, err := a.agents.CreateEnrollment(context.Background(), audit.System, org, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 5})
	if err != nil {
		t.Fatal(err)
	}
	data := sbomFile(t, "debian-12.cdx15.json")
	sbomPart := part{name: "sbom", contentType: "application/json", body: data}
	noCommit := repoContext(p, 1)
	delete(noCommit, "commit")
	cases := []struct {
		name   string
		token  string
		parts  []part
		status int
		key    string
	}{
		{"sans partie", token, nil, 400, ingest.KeyMissingPart},
		{"sbom avant context", token, []part{sbomPart, contextPart(t, repoContext(p, 1))}, 400, ingest.KeyMissingPart},
		{"sans sbom", token, []part{contextPart(t, repoContext(p, 1))}, 400, ingest.KeyMissingPart},
		{"context illisible", token, []part{{name: "context", contentType: "application/json", body: []byte("{")}, sbomPart}, 400, "error.invalid_request"},
		{"champ inconnu", token, []part{contextPart(t, map[string]any{"project_id": p.ID, "x": 1}), sbomPart}, 400, "error.invalid_request"},
		{"sans commit", token, []part{contextPart(t, noCommit), sbomPart}, 400, "error.validation"},
		{"projet d'une autre organisation", token, []part{contextPart(t, repoContext(other, 1)), sbomPart}, 404, ingest.KeyRefUnknown},
		{"agent d'une autre organisation", otherToken, []part{contextPart(t, repoContext(p, 1)), sbomPart}, 404, ingest.KeyRefUnknown},
		{"jeton d'inscription", enr.Plaintext, []part{contextPart(t, repoContext(p, 1)), sbomPart}, 401, "error.token.invalid"},
	}
	for _, c := range cases {
		r := a.upload(c.token, c.parts)
		if r.status != c.status || r.problem(t)["type"] != c.key {
			t.Errorf("%s : %d %s", c.name, r.status, r.body)
		}
	}
	// Corps non multipart.
	if r := a.api(http.MethodPost, "/api/v1/agent/ingestions", token, map[string]string{"a": "b"}); r.status != http.StatusBadRequest {
		t.Errorf("corps JSON : %d", r.status)
	}
	// Envoi au-delà de la borne : 413, sans ingestion.
	big := a.upload(token, []part{contextPart(t, repoContext(p, 2)), {name: "sbom", contentType: "application/json", body: bytes.Repeat([]byte(" "), 9<<20)}})
	if big.status != http.StatusRequestEntityTooLarge || big.problem(t)["type"] != sbom.KeyTooLarge {
		t.Errorf("envoi trop gros : %d %s", big.status, big.body)
	}
	// Une ingestion en échec expose sa clé, traduite selon la langue de la requête.
	bad := a.upload(token, []part{contextPart(t, repoContext(p, 3)), {name: "sbom", contentType: "application/json", body: []byte(`<bom/>`)}})
	if bad.status != http.StatusAccepted {
		t.Fatalf("SBOM XML : %d %s", bad.status, bad.body)
	}
	id := decodeIngestion(t, bad).ID
	if err := a.ingest.Decode(context.Background(), org, uuid.MustParse(id)); err != nil {
		t.Fatal(err)
	}
	got := decodeIngestion(t, a.api(http.MethodGet, "/api/v1/agent/ingestions/"+id, token, nil, "Accept-Language", "en"))
	if got.Status != "failed" || got.Error == nil || got.Error.Key != sbom.KeyUnsupportedFormat || got.Error.Title != "Unsupported format" {
		t.Errorf("échec %+v", got)
	}
	// Une ingestion n'est visible que de son agent.
	if r := a.api(http.MethodGet, "/api/v1/agent/ingestions/"+id, otherToken, nil); r.status != http.StatusNotFound || r.problem(t)["type"] != "error.not_found" {
		t.Errorf("ingestion d'une autre organisation : %d %s", r.status, r.body)
	}
	if r := a.api(http.MethodGet, "/api/v1/agent/ingestions/pas-un-uuid", token, nil); r.status != http.StatusBadRequest {
		t.Errorf("identifiant illisible : %d", r.status)
	}
	if strings.Contains(a.logs.String(), "bomFormat") || strings.Contains(a.logs.String(), token) {
		t.Error("contenu de SBOM ou jeton dans les journaux")
	}
}

// Écrans : onglet des instantanés, détail filtrable, téléchargements valides, isolement.
func TestSnapshotScreens(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin, viewer := a.user("admin@example.org", false), a.user("viewer@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	token, p, org := f.token, f.p, f.org.ID
	a.addMember(f.org, viewer, tenant.RoleViewer)
	ctx := context.Background()
	var snapshotID string
	for i, name := range []string{"portail-client.cdx16.json", "portail-client-ia.cdx16.json", "nope"} {
		body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":"x"}`)
		if name != "nope" {
			body = sbomFile(t, name)
		}
		r := a.upload(token, []part{contextPart(t, repoContext(p, i+1)), {name: "sbom", contentType: "application/json", body: body}})
		if r.status != http.StatusAccepted {
			t.Fatalf("%s : %d %s", name, r.status, r.body)
		}
		id := uuid.MustParse(decodeIngestion(t, r).ID)
		if err := a.ingest.Decode(ctx, org, id); err != nil {
			t.Fatal(err)
		}
		in, err := a.ingest.Get(ctx, org, f.agentID, id)
		if err != nil {
			t.Fatal(err)
		}
		if in.SnapshotID != nil {
			snapshotID = in.SnapshotID.String()
		}
	}
	// Une ingestion en attente apparaît aussi.
	if r := a.upload(token, []part{contextPart(t, repoContext(p, 9)), {name: "sbom", contentType: "application/json", body: sbomFile(t, "portail-client.cdx16.json")}}); r.status != http.StatusAccepted {
		t.Fatal(r.body)
	}
	base := "/o/org-a/projects/" + p.Slug
	for _, u := range []user{admin, viewer} {
		b := a.signIn(u)
		for _, lang := range []string{"fr", "en"} {
			for _, path := range []string{base + "/snapshots", base + "/snapshots/" + snapshotID, base + "/snapshots/" + snapshotID + "?q=jq&origin=ia&type=npm&weak=1",
				base + "/snapshots/" + snapshotID + "?q=absent", "/o/org-a/projects", base} {
				sep := "?"
				if strings.Contains(path, "?") {
					sep = "&"
				}
				pg := b.get(path + sep + "lang=" + lang)
				if pg.status != http.StatusOK {
					t.Fatalf("%s (%s) : %d %s", path, lang, pg.status, pg.body)
				}
				webtest.AssertAccessible(t, []byte(pg.body))
				webtest.AssertNoInlineCode(t, []byte(pg.body))
			}
		}
	}
	b := a.signIn(admin)
	pg := unescape(b.get(base + "/snapshots").body)
	for _, want := range []string{"Instantanés de main", "9 Syft · 3 IA", "1 identification faible", "Courant", "SBOM non conforme", "En attente",
		"Nouvel instantané", fmt.Sprintf("%07x", 2)} {
		if !strings.Contains(pg, want) {
			t.Errorf("onglet des instantanés sans %q", want)
		}
	}
	detail := unescape(b.get(base + "/snapshots/" + snapshotID + "?origin=ia").body)
	for _, want := range []string{"jquery", "82 %", "Identification faible", "pkg:generic/libfoo-interne@1.2", "Requis"} {
		if !strings.Contains(detail, want) {
			t.Errorf("détail filtré sans %q", want)
		}
	}
	if strings.Contains(detail, "lodash") {
		t.Error("le filtre d'origine laisse passer un composant Syft")
	}
	if list := unescape(b.get("/o/org-a/projects").body); !strings.Contains(list, base+"/snapshots") {
		t.Error("liste des projets sans dernier instantané")
	}

	v := testValidator(t)
	for format, want := range map[string]sbom.Format{"original": sbom.FormatCycloneDX, "cyclonedx-1.6": sbom.FormatCycloneDX, "spdx-2.3": sbom.FormatSPDX} {
		dl := b.get(base + "/snapshots/" + snapshotID + "/sbom?format=" + format)
		if dl.status != http.StatusOK || !strings.HasPrefix(dl.header.Get("Content-Disposition"), "attachment; filename=\"portail-client-") {
			t.Fatalf("téléchargement %s : %d %v", format, dl.status, dl.header)
		}
		h, err := sbom.Precheck(strings.NewReader(dl.body), sbom.Limits{MaxBytes: 1 << 24, MaxDepth: 64, MaxComponents: 1000})
		if err != nil || h.Format != want {
			t.Fatalf("téléchargement %s : %+v, %v", format, h, err)
		}
		if err := v.ValidateStrict(h.Format, h.SpecVersion, []byte(dl.body)); err != nil {
			t.Errorf("téléchargement %s invalide : %v", format, err)
		}
	}
	// Un réencodage à la fois par compte (SEC-06) ; le document tel que reçu reste servi.
	release, ok := a.reencode.Acquire("user:" + itoa(admin.ID))
	if !ok {
		t.Fatal("place de réencodage")
	}
	if dl := b.get(base + "/snapshots/" + snapshotID + "/sbom?format=spdx-2.3"); dl.status != http.StatusTooManyRequests || dl.header.Get("Retry-After") == "" {
		t.Errorf("second réencodage simultané du compte : %d", dl.status)
	}
	if dl := b.get(base + "/snapshots/" + snapshotID + "/sbom?format=original"); dl.status != http.StatusOK {
		t.Errorf("original pendant un réencodage : %d", dl.status)
	}
	release()
	if dl := b.get(base + "/snapshots/" + snapshotID + "/sbom?format=xml"); dl.status != http.StatusNotFound {
		t.Errorf("format inconnu : %d", dl.status)
	}
	for _, path := range []string{base + "/snapshots/pas-un-uuid", base + "/snapshots/" + uuid.NewString(), "/o/org-a/projects/absent/snapshots",
		base + "/snapshots/" + uuid.NewString() + "/sbom"} {
		if pg := b.get(path); pg.status != http.StatusNotFound {
			t.Errorf("%s : %d", path, pg.status)
		}
	}
	if pg := b.get(base + "/snapshots?cursor=illisible&ref=x"); pg.status != http.StatusBadRequest && pg.status != http.StatusOK {
		t.Errorf("curseur illisible : %d", pg.status)
	}
	if pg := b.get(base + "/snapshots/" + snapshotID + "?cursor=illisible"); pg.status != http.StatusBadRequest {
		t.Errorf("curseur illisible du détail : %d", pg.status)
	}

	// Un membre d'une autre organisation ne voit rien, même avec les identifiants.
	stranger := a.user("stranger@example.org", false)
	a.org("org-b", stranger)
	sb := a.signIn(stranger)
	for _, path := range []string{base + "/snapshots", base + "/snapshots/" + snapshotID, base + "/snapshots/" + snapshotID + "/sbom",
		"/o/org-b/projects/" + p.Slug + "/snapshots/" + snapshotID} {
		if pg := sb.get(path); pg.status != http.StatusNotFound {
			t.Errorf("%s par une autre organisation : %d", path, pg.status)
		}
	}
}
