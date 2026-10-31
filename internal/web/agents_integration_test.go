//go:build integration

package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/internal/web/webtest"
)

var tokenPattern = regexp.MustCompile(`<code class="token-once">(ogsbom_(?:agt|enr)_[a-z2-7]{26}_[a-z2-7]{52})</code>`)

// shownToken extrait le jeton affiché une fois sur la page.
func shownToken(t *testing.T, p page) string {
	t.Helper()
	m := tokenPattern.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("aucun jeton sur la page (%d) :\n%s", p.status, p.body)
	}
	return m[1]
}

type apiResponse struct {
	status int
	header http.Header
	body   string
}

func (r apiResponse) problem(t *testing.T) map[string]any {
	t.Helper()
	var p map[string]any
	if ct := r.header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type %q (%d) : %s", ct, r.status, r.body)
	}
	if err := json.Unmarshal([]byte(r.body), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// api appelle l'API des agents avec un jeton ; body est sérialisé en JSON s'il n'est pas
// une chaîne.
func (a *app) api(method, path, token string, body any, headers ...string) apiResponse {
	a.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			a.t.Fatal(err)
		}
		rd = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, a.srv.URL+path, rd)
	if err != nil {
		a.t.Fatal(err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
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

type enrolled struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
	Project struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	} `json:"project"`
}

func (a *app) enroll(token, host string) (apiResponse, enrolled) {
	a.t.Helper()
	r := a.api(http.MethodPost, "/api/v1/agent/enroll", token, map[string]string{"hostname": host, "version": "1.4.0"})
	var e enrolled
	if r.status == http.StatusCreated {
		if err := json.Unmarshal([]byte(r.body), &e); err != nil {
			a.t.Fatal(err)
		}
	}
	return r, e
}

// TestHostEnrollmentEndToEnd : un administrateur crée un jeton d'inscription (affiché une
// seule fois), un agent serveur s'inscrit, envoie son signal de vie et lit ses projets ;
// aucun jeton n'apparaît dans les journaux.
func TestHostEnrollmentEndToEnd(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	a.org("org-a", admin)
	b := a.signIn(admin)

	form := b.get("/o/org-a/enrollment-tokens/new")
	if form.status != http.StatusOK {
		t.Fatalf("formulaire : %d", form.status)
	}
	webtest.AssertAccessible(t, []byte(form.body))
	webtest.AssertNoInlineCode(t, []byte(form.body))
	created := b.post("/o/org-a/enrollment-tokens", url.Values{"name": {"parc-web"}, "expires_in": {"24"}, "max_uses": {"2"},
		"labels": {"env=prod, exposé-internet"}, "project": {""}})
	enr := shownToken(t, created)
	webtest.AssertAccessible(t, []byte(created.body))
	webtest.AssertNoInlineCode(t, []byte(created.body))
	list := b.get("/o/org-a/agents")
	if strings.Contains(list.body, enr) || !strings.Contains(list.body, agentPrefix(enr)) {
		t.Fatal("liste des agents : jeton affiché de nouveau, ou préfixe absent")
	}

	r, e := a.enroll(enr, "SRV-WEB-01")
	if r.status != http.StatusCreated || !strings.HasPrefix(e.Token, "ogsbom_agt_") || e.Project.Slug != "srv-web-01" {
		t.Fatalf("inscription : %d %s", r.status, r.body)
	}
	if r.header.Get("Content-Security-Policy") == "" || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("en-têtes de l'API : %v", r.header)
	}
	hb := a.api(http.MethodPost, "/api/v1/agent/heartbeat", e.Token, map[string]string{"version": "1.4.1"})
	var status struct {
		ScanRequested bool      `json:"scan_requested"`
		ServerTime    time.Time `json:"server_time"`
	}
	if hb.status != http.StatusOK || json.Unmarshal([]byte(hb.body), &status) != nil || status.ScanRequested || status.ServerTime.IsZero() {
		t.Fatalf("signal de vie : %d %s", hb.status, hb.body)
	}
	pr := a.api(http.MethodGet, "/api/v1/agent/projects", e.Token, nil)
	var projects struct {
		Projects []struct {
			Slug   string            `json:"slug"`
			Kind   string            `json:"kind"`
			Labels map[string]string `json:"labels"`
			Refs   []struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"refs"`
		} `json:"projects"`
		Page struct {
			NextCursor *string `json:"next_cursor"`
		} `json:"page"`
	}
	if pr.status != http.StatusOK || json.Unmarshal([]byte(pr.body), &projects) != nil || len(projects.Projects) != 1 {
		t.Fatalf("projets : %d %s", pr.status, pr.body)
	}
	got := projects.Projects[0]
	if got.Slug != "srv-web-01" || got.Kind != "host" || got.Labels["env"] != "prod" || got.Labels["exposé-internet"] != "" ||
		len(got.Refs) != 1 || got.Refs[0].Kind != "host" || got.Refs[0].Name != "srv-web-01" || projects.Page.NextCursor != nil {
		t.Fatalf("projet : %+v", projects)
	}

	// L'agent apparaît dans l'interface, actif, avec sa version.
	page := b.get("/o/org-a/agents/" + e.AgentID)
	body := unescape(page.body)
	if page.status != http.StatusOK || !strings.Contains(body, "1.4.1") || !strings.Contains(body, "Actif") || strings.Contains(body, e.Token) {
		t.Fatalf("fiche de l'agent : %d", page.status)
	}
	webtest.AssertAccessible(t, []byte(page.body))
	webtest.AssertNoInlineCode(t, []byte(page.body))
	proj := b.get("/o/org-a/projects/srv-web-01")
	if proj.status != http.StatusOK || !strings.Contains(unescape(proj.body), "srv-web-01") {
		t.Fatalf("fiche du projet : %d", proj.status)
	}
	webtest.AssertAccessible(t, []byte(proj.body))

	// Second usage, puis jeton épuisé : erreur traduisible, en français puis en anglais.
	if r, _ := a.enroll(enr, "srv-web-02"); r.status != http.StatusCreated {
		t.Fatalf("second usage : %d %s", r.status, r.body)
	}
	r, _ = a.enroll(enr, "srv-web-03")
	if p := r.problem(t); r.status != http.StatusUnauthorized || p["type"] != agent.KeyEnrollmentExhausted ||
		p["title"] != "Jeton d'inscription épuisé" {
		t.Fatalf("jeton épuisé : %d %v", r.status, p)
	}
	r = a.api(http.MethodPost, "/api/v1/agent/enroll", enr, map[string]string{"hostname": "x", "version": "1"}, "Accept-Language", "en")
	if p := r.problem(t); p["title"] != "Enrollment token used up" || r.header.Get("Content-Language") != "en" {
		t.Fatalf("jeton épuisé en anglais : %v", p)
	}

	logs := a.logs.String()
	for _, secret := range []string{enr, e.Token, enr[len(enr)-52:], e.Token[len(e.Token)-52:]} {
		if strings.Contains(logs, secret) {
			t.Fatal("un jeton figure dans les journaux")
		}
	}
}

func agentPrefix(token string) string { return token[:len("ogsbom_enr_")+6] }

// TestExpiredEnrollmentTokenRefused : passé sa validité, le jeton est refusé avec une clé
// traduisible.
func TestExpiredEnrollmentTokenRefused(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	_, issued, err := a.agents.CreateEnrollment(context.Background(), audit.System, o.ID,
		agent.EnrollmentInput{Name: "court", LifetimeHours: 1, MaxUses: 10})
	if err != nil {
		t.Fatal(err)
	}
	a.clock.advance(time.Hour)
	r, _ := a.enroll(issued.Plaintext, "srv")
	if p := r.problem(t); r.status != http.StatusUnauthorized || p["type"] != agent.KeyTokenExpired || p["title"] != "Jeton expiré" ||
		r.header.Get("WWW-Authenticate") == "" {
		t.Fatalf("jeton expiré : %d %v", r.status, p)
	}
}

// TestRevokedAgentTokenRefusedAtNextRequest : révoqué depuis l'interface, un jeton est
// refusé dès la requête suivante.
func TestRevokedAgentTokenRefusedAtNextRequest(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	b := a.signIn(admin)

	newForm := b.get("/o/org-a/agents/new")
	webtest.AssertAccessible(t, []byte(newForm.body))
	created := b.post("/o/org-a/agents", url.Values{"name": {"ci-atelier"}, "token_name": {"initial"}, "expires_in": {"90"}})
	tok := shownToken(t, created)
	if r := a.api(http.MethodPost, "/api/v1/agent/heartbeat", tok, map[string]string{"version": "0.9.2"}); r.status != http.StatusOK {
		t.Fatalf("signal de vie : %d %s", r.status, r.body)
	}
	page, err := a.agents.List(context.Background(), o.ID, agent.Filter{}, "", 10)
	if err != nil || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	ag, err := a.agents.Get(context.Background(), o.ID, page.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	// Rotation : un second jeton créé depuis la fiche, affiché une fois.
	second := shownToken(t, b.post("/o/org-a/agents/"+ag.ID.String()+"/tokens", url.Values{"name": {"rotation"}, "expires_in": {"0"}}))
	p := b.post("/o/org-a/agents/"+ag.ID.String()+"/tokens/"+ag.Tokens[0].ID.String()+"/revoke", nil)
	if p.status != http.StatusSeeOther || !strings.Contains(p.location, "token_revoked") {
		t.Fatalf("révocation : %d %q", p.status, p.location)
	}
	r := a.api(http.MethodPost, "/api/v1/agent/heartbeat", tok, map[string]string{"version": "0.9.2"})
	if pb := r.problem(t); r.status != http.StatusUnauthorized || pb["type"] != agent.KeyTokenRevokedErr {
		t.Fatalf("jeton révoqué : %d %v", r.status, pb)
	}
	if r := a.api(http.MethodGet, "/api/v1/agent/projects", second, nil); r.status != http.StatusOK {
		t.Fatalf("second jeton : %d %s", r.status, r.body)
	}
	show := b.get("/o/org-a/agents/" + ag.ID.String())
	if strings.Contains(show.body, tok) || strings.Contains(show.body, second) {
		t.Fatal("un secret est réaffiché sur la fiche")
	}
	if strings.Contains(a.logs.String(), tok[len(tok)-52:]) || strings.Contains(a.logs.String(), second[len(second)-52:]) {
		t.Fatal("un jeton figure dans les journaux")
	}
}

// TestAgentAPIRequestsAndErrors : jeton absent, de mauvaise nature, corps illisible,
// route inconnue et méthode refusée répondent par des problèmes RFC 9457.
func TestAgentAPIRequestsAndErrors(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	ctx := context.Background()
	_, agt, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	_, enr, err := a.agents.CreateEnrollment(ctx, audit.System, o.ID, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, method, path, token string
		body                      any
		status                    int
		key                       string
	}{
		{"sans jeton", http.MethodPost, "/api/v1/agent/heartbeat", "", map[string]string{"version": "1"}, 401, agent.KeyTokenInvalid},
		{"jeton d'agent pour s'inscrire", http.MethodPost, "/api/v1/agent/enroll", agt.Plaintext, map[string]string{"hostname": "h", "version": "1"}, 401, agent.KeyTokenInvalid},
		{"jeton d'inscription pour un signal", http.MethodPost, "/api/v1/agent/heartbeat", enr.Plaintext, map[string]string{"version": "1"}, 401, agent.KeyTokenInvalid},
		{"jeton d'inscription pour les projets", http.MethodGet, "/api/v1/agent/projects", enr.Plaintext, nil, 401, agent.KeyTokenInvalid},
		{"corps illisible", http.MethodPost, "/api/v1/agent/heartbeat", agt.Plaintext, "{", 400, "error.invalid_request"},
		{"corps trop gros", http.MethodPost, "/api/v1/agent/heartbeat", agt.Plaintext, `{"version":"` + strings.Repeat("x", 70<<10) + `"}`, 400, "error.invalid_request"},
		{"version invalide", http.MethodPost, "/api/v1/agent/heartbeat", agt.Plaintext, map[string]string{"version": "a b"}, 400, "error.validation"},
		{"nom d'hôte invalide", http.MethodPost, "/api/v1/agent/enroll", enr.Plaintext, map[string]string{"hostname": "a/b", "version": "1"}, 400, "error.validation"},
		{"taille de page", http.MethodGet, "/api/v1/agent/projects?limit=500", agt.Plaintext, nil, 400, "error.invalid_limit"},
		{"curseur", http.MethodGet, "/api/v1/agent/projects?cursor=x", agt.Plaintext, nil, 400, "error.invalid_cursor"},
		{"paramètre illisible", http.MethodGet, "/api/v1/agent/projects?limit=abc", agt.Plaintext, nil, 400, "error.invalid_request"},
		{"route inconnue", http.MethodGet, "/api/v1/agent/inconnue", agt.Plaintext, nil, 404, "error.not_found"},
		{"méthode refusée", http.MethodGet, "/api/v1/agent/enroll", agt.Plaintext, nil, 405, "error.method_not_allowed"},
		{"API utilisateur vide", http.MethodGet, "/api/v1/orgs/org-a/x", agt.Plaintext, nil, 404, "error.not_found"},
	} {
		r := a.api(c.method, c.path, c.token, c.body)
		if r.status != c.status {
			t.Errorf("%s : %d, attendu %d (%s)", c.name, r.status, c.status, r.body)
			continue
		}
		if p := r.problem(t); p["type"] != c.key || p["title"] == "" || p["request_id"] == "" {
			t.Errorf("%s : %v", c.name, p)
		}
	}
	if strings.Contains(a.logs.String(), agt.Plaintext[len(agt.Plaintext)-52:]) || strings.Contains(a.logs.String(), enr.Plaintext[len(enr.Plaintext)-52:]) {
		t.Fatal("un jeton figure dans les journaux")
	}
}

// TestAgentRateLimitIsPerToken : un agent qui dépasse sa limite reçoit 429 sans gêner un
// autre agent de même IP ; les jetons refusés sont limités par IP.
func TestAgentRateLimitIsPerToken(t *testing.T) {
	t.Parallel()
	a := newApp(t, func(o *RouterOptions) { o.AgentAPI.RateLimit, o.AgentAPI.FailureRateLimit = 3, 2 })
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	ctx := context.Background()
	_, t1, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, "ci-1", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	_, t2, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, "ci-2", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if r := a.api(http.MethodGet, "/api/v1/agent/projects", t1.Plaintext, nil); r.status != http.StatusOK {
			t.Fatalf("requête %d : %d", i, r.status)
		}
	}
	r := a.api(http.MethodGet, "/api/v1/agent/projects", t1.Plaintext, nil)
	if p := r.problem(t); r.status != http.StatusTooManyRequests || p["type"] != "error.too_many_requests" || r.header.Get("Retry-After") == "" {
		t.Fatalf("au-delà de la limite : %d %v", r.status, p)
	}
	if r := a.api(http.MethodGet, "/api/v1/agent/projects", t2.Plaintext, nil); r.status != http.StatusOK {
		t.Fatalf("autre agent de même IP : %d", r.status)
	}
	bad := mustToken(t, agent.KindAgent)
	for i := range 2 {
		if r := a.api(http.MethodGet, "/api/v1/agent/projects", bad, nil); r.status != http.StatusUnauthorized {
			t.Fatalf("refus %d : %d", i, r.status)
		}
	}
	if r := a.api(http.MethodGet, "/api/v1/agent/projects", bad, nil); r.status != http.StatusTooManyRequests {
		t.Fatalf("refus au-delà de la limite : %d", r.status)
	}
	if r := a.api(http.MethodGet, "/api/v1/agent/projects", t2.Plaintext, nil); r.status != http.StatusOK {
		t.Fatalf("agent authentifié après des refus de même IP : %d", r.status)
	}
}

func mustToken(t *testing.T, kind agent.TokenKind) string {
	t.Helper()
	tok, err := agent.NewToken(kind)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Plaintext
}

// TestProjectScreens : un administrateur crée, modifie, confie et archive un dépôt ; un
// lecteur consulte sans modifier ; chaque page est accessible, sans code en ligne, en
// français et en anglais.
func TestProjectScreens(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin, viewer := a.user("admin@example.org", false), a.user("viewer@example.org", false)
	o := a.org("org-a", admin)
	a.addMember(o, viewer, tenant.RoleViewer)
	ad := a.signIn(admin)

	p := ad.post("/o/org-a/projects", url.Values{"kind": {"repo"}, "name": {"Portail client"}, "description": {"Site public"},
		"labels": {"env=prod, pci"}, "forge_url": {"https://git.example.org/web/portail"}, "branches": {"main\nrelease/1.x"}, "tags": {"v1.0"}})
	if p.status != http.StatusSeeOther || p.location != "/o/org-a/projects/portail-client?done=project_created" {
		t.Fatalf("création : %d %q\n%s", p.status, p.location, p.body)
	}
	if p := ad.post("/o/org-a/projects", url.Values{"kind": {"repo"}, "name": {"x"}, "labels": {"=bad"}, "branches": {"main"}}); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(unescape(p.body), "Une étiquette s'écrit") {
		t.Errorf("étiquette invalide : %d", p.status)
	}
	if p := ad.post("/o/org-a/projects", url.Values{"kind": {"host"}, "name": {"srv"}, "host_ref": {"srv db"}}); p.status != http.StatusUnprocessableEntity {
		t.Errorf("hôte invalide : %d", p.status)
	}
	if p := ad.post("/o/org-a/projects", url.Values{"kind": {"host"}, "name": {"Base"}, "host_ref": {"db-01"}}); p.status != http.StatusSeeOther {
		t.Errorf("serveur : %d %s", p.status, p.body)
	}
	if _, _, err := a.agents.CreateRepoAgent(context.Background(), audit.System, o.ID, "ci-atelier", "initial", 90); err != nil {
		t.Fatal(err)
	}
	repoAgents, err := a.agents.RepoAgents(context.Background(), o.ID)
	if err != nil || len(repoAgents) != 1 {
		t.Fatal(repoAgents, err)
	}
	if p := ad.post("/o/org-a/projects/portail-client/agent", url.Values{"agent": {repoAgents[0].ID.String()}}); p.status != http.StatusSeeOther {
		t.Fatalf("affectation : %d %s", p.status, p.body)
	}
	if p := ad.post("/o/org-a/projects/portail-client/agent", url.Values{"agent": {"pas-un-uuid"}}); p.status != http.StatusUnprocessableEntity {
		t.Errorf("agent illisible : %d", p.status)
	}
	if p := ad.post("/o/org-a/projects/portail-client/settings", url.Values{"name": {"Portail client"}, "description": {"Site public"},
		"labels": {"env=prod"}, "forge_url": {""}, "branches": {"main"}, "tags": {""}}); p.status != http.StatusSeeOther {
		t.Fatalf("modification : %d %s", p.status, p.body)
	}
	got, err := a.projects.Get(context.Background(), o.ID, "portail-client")
	if err != nil || got.Labels.String() != "env=prod" || got.ForgeURL != "" || got.Agent == nil || got.Agent.Name != "ci-atelier" {
		t.Fatalf("projet modifié : %+v %v", got, err)
	}

	pages := []string{"/o/org-a/projects", "/o/org-a/projects?kind=host&label=env%3Dprod&q=a", "/o/org-a/projects/new",
		"/o/org-a/projects/new?kind=host", "/o/org-a/projects/portail-client?done=project_created", "/o/org-a/projects/portail-client/settings",
		"/o/org-a/projects/base", "/o/org-a/agents", "/o/org-a/agents?kind=repo", "/o/org-a/agents/new", "/o/org-a/enrollment-tokens/new?project=base"}
	for _, lang := range []string{"fr", "en"} {
		for _, path := range pages {
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			pg := ad.get(path + sep + "lang=" + lang)
			if pg.status != http.StatusOK {
				t.Errorf("%s (%s) : %d", path, lang, pg.status)
				continue
			}
			webtest.AssertAccessible(t, []byte(pg.body))
			webtest.AssertNoInlineCode(t, []byte(pg.body))
		}
	}
	if pg := ad.get("/o/org-a/projects?lang=en"); !strings.Contains(pg.body, "Portail client") || !strings.Contains(pg.body, "Repository") {
		t.Error("liste en anglais")
	}

	if p := ad.post("/o/org-a/projects/portail-client/archive", nil); p.status != http.StatusSeeOther {
		t.Fatalf("archivage : %d", p.status)
	}
	if pg := ad.get("/o/org-a/projects"); strings.Contains(pg.body, "portail-client") {
		t.Error("projet archivé encore listé")
	}
	if pg := ad.get("/o/org-a/projects?archived=1"); !strings.Contains(pg.body, "portail-client") {
		t.Error("projet archivé absent de la liste des archivés")
	}
	if pg := ad.get("/o/org-a/projects/portail-client/settings"); pg.status != http.StatusOK {
		t.Errorf("paramètres d'un projet archivé : %d", pg.status)
	} else {
		webtest.AssertAccessible(t, []byte(pg.body))
	}
	if p := ad.post("/o/org-a/projects/portail-client/unarchive", nil); p.status != http.StatusSeeOther {
		t.Fatalf("réactivation : %d", p.status)
	}
	if pg := ad.get("/o/org-a/projects/absent"); pg.status != http.StatusNotFound {
		t.Errorf("projet absent : %d", pg.status)
	}

	// Le lecteur consulte, sans aucune action d'administration.
	v := a.signIn(viewer)
	for _, path := range []string{"/o/org-a/projects", "/o/org-a/projects/portail-client", "/o/org-a/agents"} {
		pg := v.get(path)
		if pg.status != http.StatusOK || strings.Contains(pg.body, "/settings\"") || strings.Contains(pg.body, "/projects/new\"") ||
			strings.Contains(pg.body, "enrollment-tokens/new") || strings.Contains(pg.body, "/agent\"") || strings.Contains(pg.body, "/agents/new\"") {
			t.Errorf("lecteur %s : %d", path, pg.status)
		}
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/o/org-a/projects/new"}, {http.MethodPost, "/o/org-a/projects"},
		{http.MethodGet, "/o/org-a/projects/portail-client/settings"}, {http.MethodPost, "/o/org-a/projects/portail-client/archive"},
		{http.MethodPost, "/o/org-a/projects/portail-client/agent"}, {http.MethodGet, "/o/org-a/agents/new"},
		{http.MethodPost, "/o/org-a/agents"}, {http.MethodGet, "/o/org-a/enrollment-tokens/new"},
		{http.MethodPost, "/o/org-a/enrollment-tokens"},
	} {
		var pg page
		if c.method == http.MethodGet {
			pg = v.get(c.path)
		} else {
			pg = v.post(c.path, url.Values{"name": {"x"}, "kind": {"repo"}, "branches": {"main"}})
		}
		if pg.status != http.StatusForbidden {
			t.Errorf("lecteur %s %s : %d", c.method, c.path, pg.status)
		}
	}

	audit := unescape(ad.get("/o/org-a/audit").body)
	for _, want := range []string{"Projet portail-client créé", "Projet portail-client modifié", "Agent du projet portail-client : ci-atelier",
		"Projet portail-client archivé", "Projet portail-client réactivé"} {
		if !strings.Contains(audit, want) {
			t.Errorf("journal sans « %s »", want)
		}
	}
}
