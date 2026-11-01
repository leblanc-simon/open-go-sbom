//go:build integration

package web

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/hostagent"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/vulntest"
	"leblanc.io/lotor/internal/web/webtest"
)

const (
	imageAlpine = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imageUbuntu = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	busybox     = "pkg:apk/alpine/busybox@1.36.1-r29?arch=x86_64&distro=alpine-3.20.3"
)

// dockerAPI imite l'API Docker d'un moteur sur une socket Unix : quatre conteneurs, deux
// images ; l'export d'une image renvoie son nom de fichier de testdata/sbom.
type dockerAPI struct {
	mu         sync.Mutex
	containers []map[string]any
}

func (d *dockerAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	enc := json.NewEncoder(w)
	switch {
	case r.URL.Path == "/version":
		_ = enc.Encode(map[string]any{"Version": "29.0.0", "Components": []map[string]any{{"Name": "Engine"}}})
	case r.URL.Path == "/containers/json":
		_ = enc.Encode(d.containers)
	case strings.HasSuffix(r.URL.Path, "/json"):
		_ = enc.Encode(map[string]any{"State": map[string]any{"StartedAt": "2026-10-31T08:00:00Z"}})
	case r.URL.Path == "/images/"+imageAlpine+"/get":
		_, _ = io.WriteString(w, "alpine-3.20.syft.json")
	case r.URL.Path == "/images/"+imageUbuntu+"/get":
		_, _ = io.WriteString(w, "ubuntu-24.04.syft.json")
	default:
		http.NotFound(w, r)
	}
}

func (d *dockerAPI) set(containers ...map[string]any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.containers = containers
}

func dockerContainer(id, name, project, service, image string) map[string]any {
	c := map[string]any{"Id": id, "Names": []string{"/" + name}, "Image": "registry.example.org/" + name, "ImageID": image, "State": "running"}
	if project != "" {
		c["Labels"] = map[string]string{hostagent.LabelComposeProject: project, hostagent.LabelComposeService: service}
	}
	return c
}

// sbomImages remplace Syft pour les images : l'archive exportée nomme un SBOM Syft de
// testdata/sbom, dont l'empreinte est calculée comme par l'agent.
type sbomImages struct {
	t     *testing.T
	mu    sync.Mutex
	scans int
}

func (s *sbomImages) ScanImage(_ context.Context, archive, _ string) (hostagent.Inventory, error) {
	name, err := os.ReadFile(archive)
	if err != nil {
		return hostagent.Inventory{}, err
	}
	data := sbomFile(s.t, string(name))
	doc, err := sbomsyft.Decode(sbom.FormatSyft, data)
	if err != nil {
		return hostagent.Inventory{}, err
	}
	s.mu.Lock()
	s.scans++
	s.mu.Unlock()
	return hostagent.Inventory{SBOM: data, Fingerprint: sbom.Fingerprint(doc.Components), Components: len(doc.Components),
		Started: time.Now().UTC()}, nil
}

// serveDocker sert api sur une socket Unix au chemin court et renvoie ce chemin.
func serveDocker(t *testing.T, api *dockerAPI) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(api)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return path
}

// TestContainersEndToEnd : un vrai lotor-host-agent, inventaire des conteneurs activé
// sur un moteur Docker simulé, inventorie l'hôte et ses conteneurs : trois services sur
// deux images donnent trois projets enfants et deux scans d'image, les deux répliques
// d'un service un seul projet. La fiche de l'hôte montre ses conteneurs et leurs
// constats par périmètre ; listes et recherche écartent les conteneurs sauf s'ils sont
// inclus ; un conteneur arrêté depuis plus de N jours est archivé, puis revient.
func TestContainersEndToEnd(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	a.decoder()
	admin, outsider := a.user("admin@example.org", false), a.user("autre@example.org", false)
	o := a.org("org-a", admin)
	a.org("org-b", outsider)
	b := a.signIn(admin)
	srv, caFile := a.tlsAPI(nil)
	created := b.post("/o/org-a/enrollment-tokens", url.Values{"name": {"parc"}, "expires_in": {"24"}, "max_uses": {"1"},
		"project": {""}, "team": {a.defaultTeam(o.ID).String()}})
	enr := shownToken(t, created)

	api := &dockerAPI{}
	api.set(
		dockerContainer("c1", "shop-web-1", "shop", "web", imageAlpine),
		dockerContainer("c2", "shop-web-2", "shop", "web", imageAlpine),
		dockerContainer("c3", "shop-api-1", "shop", "api", imageAlpine),
		dockerContainer("c4", "cache", "", "", imageUbuntu),
	)
	socket := serveDocker(t, api)
	images := &sbomImages{t: t}
	ag := a.hostAgent(srv, caFile, enr, agentclient.TLSOptions{}, withContainers(socket, images))

	ctx := context.Background()
	res, err := ag.Cycle(ctx)
	if err != nil || res.Outcome != hostagent.OutcomeSent || res.Containers == nil {
		t.Fatalf("premier cycle : %+v %v", res, err)
	}
	if c := *res.Containers; c.Workloads != 3 || c.Images != 2 || c.Sent != 3 || c.Failed != 0 || images.scans != 2 {
		t.Fatalf("conteneurs : %+v, %d scans", c, images.scans)
	}
	host, err := a.projects.Get(ctx, o.ID, tenant.AllTeams(), "srv-agent-01")
	if err != nil {
		t.Fatal(err)
	}
	children, err := a.projects.Children(ctx, o.ID, tenant.AllTeams(), host.ID)
	if err != nil || len(children) != 3 {
		t.Fatalf("projets enfants : %+v %v", children, err)
	}
	for _, c := range children {
		if c.TeamID != host.TeamID || c.Parent.ID != host.ID {
			t.Errorf("enfant %s : équipe %s, parent %+v", c.Slug, c.TeamID, c.Parent)
		}
	}
	if res, err = ag.Cycle(ctx); err != nil || res.Containers.Confirmed != 3 || res.Containers.Images != 0 || images.scans != 2 {
		t.Fatalf("second cycle : %+v %v", res.Containers, err)
	}

	// Une vulnérabilité de busybox, présent dans l'image alpine des deux services.
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), vulntest.Rule{PURL: busybox, Vuln: vuln.Vulnerability{ID: "CVE-2099-1000",
		Severity: vuln.SeverityHigh, Risk: 60}, Match: vuln.Match{FixState: vuln.FixFixed, FixedVersions: []string{"1.36.1-r30"}, Risk: 60}})
	for _, c := range children {
		if out, err := s.analyzer.Analyze(ctx, o.ID, a.mainRef(o.ID, c.ID)); err != nil || out != finding.OutcomeAnalyzed {
			t.Fatalf("analyse de %s : %s %v", c.Slug, out, err)
		}
	}

	page := b.get("/o/org-a/projects/srv-agent-01")
	body := unescape(page.body)
	for _, want := range []string{"Conteneurs et constats par périmètre", "3 conteneurs", "shop/web", "shop/api", "cache",
		"2 répliques", "registry.example.org/shop-web-", "En cours d'exécution", "Total : hôte et conteneurs actifs"} {
		if !strings.Contains(body, want) {
			t.Errorf("fiche de l'hôte : %q absent", want)
		}
	}
	webtest.AssertAccessible(t, []byte(page.body))
	webtest.AssertNoInlineCode(t, []byte(page.body))
	web := "/o/org-a/projects/srv-agent-01-shop-web"
	for _, lang := range []string{"fr", "en"} {
		pg := b.get(web + "?lang=" + lang)
		if pg.status != http.StatusOK {
			t.Fatalf("fiche du conteneur (%s) : %d", lang, pg.status)
		}
		webtest.AssertAccessible(t, []byte(pg.body))
		webtest.AssertNoInlineCode(t, []byte(pg.body))
		want := []string{"Projet Compose", "Conteneur de", "shop-web-2"}
		if lang == "en" {
			want = []string{"Compose project", "Container of", "shop-web-2"}
		}
		for _, w := range want {
			if !strings.Contains(unescape(pg.body), w) {
				t.Errorf("fiche du conteneur (%s) : %q absent", lang, w)
			}
		}
	}
	if settings := b.get(web + "/settings"); !strings.Contains(unescape(settings.body), "suit l'équipe de son hôte") {
		t.Errorf("paramètres d'un conteneur : %d", settings.status)
	}
	if moved := b.post(web+"/team", url.Values{"team": {a.defaultTeam(o.ID).String()}}); moved.status == http.StatusSeeOther {
		t.Error("un conteneur rattaché seul")
	}
	// Listes et recherche : conteneurs écartés, sauf s'ils sont inclus.
	if list := b.get("/o/org-a/projects"); strings.Contains(list.body, "srv-agent-01-shop-web") {
		t.Error("conteneur dans la liste par défaut")
	}
	if list := b.get("/o/org-a/projects?containers=1"); !strings.Contains(list.body, "srv-agent-01-shop-web") {
		t.Error("conteneur absent de la liste avec les conteneurs")
	}
	if found := b.get("/o/org-a/search?q=busybox"); strings.Contains(found.body, "srv-agent-01-shop-web") {
		t.Error("conteneur dans la recherche par défaut")
	}
	found := b.get("/o/org-a/search?q=busybox&containers=1")
	if !strings.Contains(found.body, "srv-agent-01-shop-web") || !strings.Contains(unescape(found.body), "Conteneurs inclus") {
		t.Errorf("recherche avec les conteneurs : %d", found.status)
	}
	webtest.AssertAccessible(t, []byte(found.body))
	// Isolement : un compte d'une autre organisation ne voit pas la fiche.
	if pg := a.signIn(outsider).get(web); pg.status != http.StatusNotFound {
		t.Errorf("autre organisation : %d", pg.status)
	}

	// Le service api s'arrête : archivé après N jours, il revient quand il redémarre.
	api.set(dockerContainer("c1", "shop-web-1", "shop", "web", imageAlpine), dockerContainer("c4", "cache", "", "", imageUbuntu))
	a.clock.advance(project.DefaultArchiveAfter + time.Hour)
	if res, err = ag.Cycle(ctx); err != nil || res.Containers.Workloads != 2 {
		t.Fatalf("service arrêté : %+v %v", res.Containers, err)
	}
	archiver := project.NewArchiver(a.tdb.App, project.DefaultArchiveAfter, a.clock.Now)
	if n, err := archiver.Archive(ctx, o.ID); err != nil || n != 1 {
		t.Fatalf("archivage : %d %v", n, err)
	}
	if pg := b.get("/o/org-a/projects/srv-agent-01-shop-api"); !strings.Contains(unescape(pg.body), "Conteneur archivé pour absence") {
		t.Error("fiche d'un conteneur archivé pour absence")
	}
	if pg := b.get("/o/org-a/projects/srv-agent-01"); !strings.Contains(unescape(pg.body), "Archivé (absent)") {
		t.Error("conteneur archivé absent de la fiche de l'hôte")
	}
	api.set(dockerContainer("c5", "shop-api-1", "shop", "api", imageAlpine))
	if res, err = ag.Cycle(ctx); err != nil || res.Containers.Confirmed != 1 {
		t.Fatalf("retour : %+v %v", res.Containers, err)
	}
	var archived int
	if err := a.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM projects WHERE kind = 'container' AND archived_at IS NOT NULL`).Scan(&archived)
	}); err != nil || archived != 0 {
		t.Errorf("%d conteneurs archivés après le retour : %v", archived, err)
	}
}

// withContainers active l'inventaire des conteneurs d'un agent construit par hostAgent.
func withContainers(socket string, images hostagent.ImageScanner) func(*hostagent.Options) {
	return func(o *hostagent.Options) {
		o.Config.Containers = hostagent.Containers{Enabled: true, Sockets: []string{socket}, MaxImageMiB: 16, Timeout: 5 * time.Second}
		o.Engines, o.ImageScanner = hostagent.Engines(o.Config.Containers), images
	}
}

// TestContainersAPI : le signalement des conteneurs par l'API des agents. Un corps de
// plus de 64 Kio passe (borne propre de 1 Mio) et 501 identités sont refusées par la
// validation ; un jeton d'inscription n'y a pas accès ; la réponse donne le projet et la
// référence de chaque conteneur.
func TestContainersAPI(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	b := a.signIn(admin)
	created := b.post("/o/org-a/enrollment-tokens", url.Values{"name": {"parc"}, "expires_in": {"24"}, "max_uses": {"1"},
		"project": {""}, "team": {a.defaultTeam(o.ID).String()}})
	enr := shownToken(t, created)
	if r := a.api(http.MethodPost, "/api/v1/agent/containers", enr, map[string]any{"version": "1", "containers": []any{}}); r.status != http.StatusUnauthorized {
		t.Errorf("jeton d'inscription : %d", r.status)
	}
	_, e := a.enroll(enr, "srv-api")
	sighting := func(key string) map[string]any {
		return map[string]any{"key": key, "engine": "docker", "names": []string{strings.ReplaceAll(key, "/", "-")}, "replicas": 1,
			"image": "nginx:1.27", "image_id": imageAlpine, "compose_project": "shop", "compose_service": "web"}
	}
	r := a.api(http.MethodPost, "/api/v1/agent/containers", e.Token, map[string]any{"version": "1.0.0", "containers": []any{sighting("shop/web")}})
	if r.status != http.StatusOK {
		t.Fatalf("signalement : %d %s", r.status, r.body)
	}
	var out struct {
		Containers []struct {
			Key     string `json:"key"`
			Project struct{ ID, Slug string }
			RefID   string `json:"ref_id"`
			Ignored bool   `json:"ignored"`
		} `json:"containers"`
	}
	if err := json.Unmarshal([]byte(r.body), &out); err != nil || len(out.Containers) != 1 || out.Containers[0].Project.Slug != "srv-api-shop-web" ||
		out.Containers[0].RefID == "" || out.Containers[0].Ignored {
		t.Fatalf("réponse : %s %v", r.body, err)
	}
	many := make([]any, 501)
	for i := range many {
		many[i] = sighting("svc" + strings.Repeat("x", i%40) + string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	body, _ := json.Marshal(map[string]any{"version": "1.0.0", "containers": many})
	if len(body) <= 64<<10 {
		t.Fatalf("corps de %d octets : le test exige plus de 64 Kio", len(body))
	}
	r = a.api(http.MethodPost, "/api/v1/agent/containers", e.Token, string(body))
	if r.status != http.StatusBadRequest || !strings.Contains(r.problem(t)["detail"].(string), "500 identités") {
		t.Errorf("501 identités : %d %s", r.status, r.body)
	}
	bad := sighting("shop/web")
	bad["image_id"] = "latest"
	if r = a.api(http.MethodPost, "/api/v1/agent/containers", e.Token, map[string]any{"version": "1", "containers": []any{bad}}); r.status != http.StatusBadRequest {
		t.Errorf("empreinte d'image invalide : %d %s", r.status, r.body)
	}
	if r = a.api(http.MethodPost, "/api/v1/agent/containers", e.Token, strings.Repeat(" ", 2<<20)); r.status == http.StatusOK {
		t.Errorf("corps de 2 Mio : %d", r.status)
	}
}
