//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/forge"
	"leblanc.io/lotor/internal/llm/llmtest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/repoagent"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

const jqueryMin = "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\n" +
	"!function(e,t){\"use strict\";var f=\"3.4.1\"}();\n"

// TestRepoAgentAIEnrichmentAgainstServer : un dépôt réglé « fournisseur externe » est
// enrichi par l'agent dépôt réel (modèle scénarisé), le serveur range le composant IA avec
// sa preuve et le statut d'enrichissement, l'API des agents rend ses composants IA à
// l'agent qui sert le projet (404 pour tout autre), et la fiche composant montre la
// preuve. Rien du fichier exclu ni du jeton n'atteint le fournisseur.
func TestRepoAgentAIEnrichmentAgainstServer(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	ag, tok, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, nil, "forge", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	_, otherTok, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, nil, "other", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.projects.Create(ctx, audit.System, o.ID, a.inTeam(o.ID, project.Input{
		Kind: project.KindRepo, Name: "App", ForgeURL: "https://forge.test/acme/app", Branches: []string{"main"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.projects.AssignAgent(ctx, audit.System, o.ID, p.Slug, &ag.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.projects.SetAIMode(ctx, audit.System, o.ID, p.Slug, project.AIExternal, true); err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	work, bare := filepath.Join(base, "work"), filepath.Join(base, "app.git")
	localGit(t, base, "init", "--quiet", work)
	localGit(t, base, "init", "--quiet", "--bare", bare)
	writeRepoFile(t, filepath.Join(work, ".env"), "TOKEN=LOTOR-CANARY-E2E-ENV\n")
	c1 := commitFile(t, work, bare, "public/js/vendor/jquery.min.js", jqueryMin)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	gh, err := forge.NewGitHub(forge.GitHubConfig{Name: "github", AppID: "1", PrivateKey: key, WebhookSecret: []byte("s")})
	if err != nil {
		t.Fatal(err)
	}
	provider := localForge{GitHub: gh, t: t, bare: bare}
	server, err := repoagent.NewServer(repoagent.ServerConfig{URL: a.srv.URL, Timeout: 30 * time.Second, Retries: 1}, tok.Plaintext,
		repoagent.ServerOptions{Version: "1.0.0", Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	cands := []repoagent.Candidate{
		{Name: "jquery", Version: "3.4.1", PURL: "pkg:npm/jquery@3.4.1", File: "public/js/vendor/jquery.min.js", Line: 1,
			Excerpt: "jQuery v3.4.1", Confidence: 0.97},
		{Name: "jquery", Version: "3.7.1", PURL: "pkg:npm/jquery@3.7.1", File: "public/js/vendor/jquery.min.js", Line: 1,
			Excerpt: "jQuery v3.7.1", Confidence: 0.99},
	}
	script := &llmtest.Script{ModelName: "claude-test", IsExternal: true, Steps: []llmtest.Step{
		llmtest.Tools(llmtest.Call{Name: "read_file", Input: map[string]string{"path": ".env"}},
			llmtest.Call{Name: "list_dir", Input: map[string]string{"path": "."}}),
		llmtest.Tools(llmtest.Call{Name: "submit_candidates", Input: map[string]any{"candidates": cands}}),
	}}
	rec := llmtest.Record(script)
	ra, err := repoagent.New(repoagent.Options{
		Server: server, Forges: []forge.Provider{provider}, Logger: newTextLogger(&syncBuffer{}), Version: "1.0.0",
		Work: repoagent.WorkConfig{Dir: t.TempDir(), Parallelism: 1, QueueSize: 10, CloneTimeout: time.Minute,
			ScanTimeout: 2 * time.Minute, MaxCloneMiB: 64, Git: "git"},
		Catchup: repoagent.CatchupConfig{Interval: time.Hour, MaxCommits: 20},
		AI: repoagent.AIConfig{MaxTurns: 10, MaxInputTokens: 100_000, MaxOutputTokens: 10_000, MaxReadKiB: 256, ResponseTokens: 4096,
			Timeout: time.Minute, FullInterval: time.Hour},
		ExternalModel: rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error)
	go func() { done <- ra.Run(runCtx) }()
	snapshotFor(t, a, o.ID, p.ID.String(), c1)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	sent := rec.Sent()
	for _, leak := range []string{"LOTOR-CANARY-E2E-ENV", tok.Plaintext, base} {
		if strings.Contains(sent, leak) {
			t.Fatalf("fuite vers le fournisseur : %q", leak)
		}
	}

	got, err := a.projects.Get(ctx, o.ID, tenant.AllTeams(), p.Slug)
	if err != nil {
		t.Fatal(err)
	}
	states, err := a.inv.RefStates(ctx, o.ID, p.ID)
	if err != nil || len(states) != 1 || states[0].Current == nil {
		t.Fatalf("%+v %v", states, err)
	}
	cur := states[0].Current
	if cur.Enrichment != sbom.EnrichmentComplete || cur.EnrichmentModel != "claude-test" || cur.Counts.IA != 1 {
		t.Fatalf("instantané : %+v", cur)
	}
	ref := got.Refs[0].ID

	// API des agents : composants IA de l'instantané courant, à l'agent du projet seul.
	r := a.api(http.MethodGet, "/api/v1/agent/refs/"+ref.String()+"/ai-components", tok.Plaintext, nil)
	if r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.body)
	}
	var list struct {
		Components []struct {
			PURL, File, Excerpt, Model string
			Line                       int
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(r.body), &list); err != nil || len(list.Components) != 1 {
		t.Fatalf("%v %s", err, r.body)
	}
	if c := list.Components[0]; c.PURL != "pkg:npm/jquery@3.4.1" || c.File != "public/js/vendor/jquery.min.js" || c.Line != 1 ||
		c.Excerpt != "jQuery v3.4.1" || c.Model != "claude-test" {
		t.Fatalf("%+v", c)
	}
	for _, path := range []string{"/api/v1/agent/refs/" + ref.String() + "/ai-components", "/api/v1/agent/refs/" + uuid.NewString() + "/ai-components"} {
		if r := a.api(http.MethodGet, path, otherTok.Plaintext, nil); r.status != http.StatusNotFound {
			t.Fatalf("%s autre agent : %d", path, r.status)
		}
	}
	if r := a.api(http.MethodGet, "/api/v1/agent/refs/"+ref.String()+"/ai-components", "", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("sans jeton : %d", r.status)
	}

	// Fiche composant : bloc « preuve », accessible ; fiche projet : compte par origine.
	var compID uuid.UUID
	if err := a.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT id FROM components WHERE purl = 'pkg:npm/jquery@3.4.1'`).Scan(&compID)
	}); err != nil {
		t.Fatal(err)
	}
	b := a.signIn(admin)
	page := b.get("/o/org-a/components/" + compID.String())
	for _, want := range []string{"Preuve de la détection IA", "public/js/vendor/jquery.min.js", "jQuery v3.4.1", "claude-test",
		"Confiance élevée", `href="#proof-1"`} {
		if !strings.Contains(page.body, want) {
			t.Errorf("fiche composant sans %q", want)
		}
	}
	webtest.AssertAccessible(t, []byte(page.body))
	webtest.AssertNoInlineCode(t, []byte(page.body))
	show := b.get("/o/org-a/projects/" + p.Slug)
	for _, want := range []string{"Inventaire courant", "Fournisseur externe autorisé", "Enrichissement IA complet"} {
		if !strings.Contains(show.body, want) {
			t.Errorf("fiche projet sans %q", want)
		}
	}
	webtest.AssertAccessible(t, []byte(show.body))
	snap := b.get("/o/org-a/projects/" + p.Slug + "/snapshots/" + cur.ID.String())
	if !strings.Contains(snap.body, "claude-test") {
		t.Error("instantané sans le modèle de l'enrichissement")
	}
}

func writeRepoFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestProjectAISettings : réglage par un administrateur d'équipe (sauf le fournisseur
// externe, réservé à un administrateur d'organisation : 403), interdiction par l'instance,
// journal d'audit, transmission du réglage effectif à l'agent.
func TestProjectAISettings(t *testing.T) {
	t.Parallel()
	for _, forbid := range []bool{false, true} {
		a := newApp(t, func(o *RouterOptions) {
			o.Identity.ForbidExternalAI = forbid
			o.AgentAPI.ForbidExternalAI = forbid
		})
		ctx := context.Background()
		admin := a.user("admin@example.org", false)
		lead := a.user("lead@example.org", false)
		o := a.org("org-a", admin)
		a.addTeamMember(o, lead, tenant.TeamAdmin)
		ag, tok, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, nil, "forge", "initial", 90)
		if err != nil {
			t.Fatal(err)
		}
		p, err := a.projects.Create(ctx, audit.System, o.ID, a.inTeam(o.ID, project.Input{
			Kind: project.KindRepo, Name: "App", ForgeURL: "https://forge.test/acme/app", Branches: []string{"main"},
		}))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.projects.AssignAgent(ctx, audit.System, o.ID, p.Slug, &ag.ID); err != nil {
			t.Fatal(err)
		}
		settings := "/o/org-a/projects/" + p.Slug + "/settings"
		action := "/o/org-a/projects/" + p.Slug + "/ai"

		lb := a.signIn(lead)
		pg := lb.get(settings)
		if !strings.Contains(pg.body, "Enrichissement IA") || !strings.Contains(pg.body, `value="external" aria-describedby="project-ai-external-hint" disabled`) {
			t.Fatalf("réglage du chef d'équipe : %s", pg.body)
		}
		webtest.AssertAccessible(t, []byte(pg.body))
		if r := lb.post(action, url.Values{"ai_mode": {"local"}}); r.status != http.StatusSeeOther {
			t.Fatalf("local : %d", r.status)
		}
		if r := lb.post(action, url.Values{"ai_mode": {"external"}}); r.status != http.StatusForbidden {
			t.Fatalf("externe par un chef d'équipe : %d", r.status)
		}
		ab := a.signIn(admin)
		r := ab.post(action, url.Values{"ai_mode": {"external"}})
		if forbid {
			if r.status != http.StatusUnprocessableEntity || !strings.Contains(r.body, "interdit tout fournisseur") {
				t.Fatalf("externe interdit : %d", r.status)
			}
		} else if r.status != http.StatusSeeOther {
			t.Fatalf("externe par l'administrateur : %d %s", r.status, r.body)
		}
		if r := ab.post(action, url.Values{"ai_mode": {"bogus"}}); r.status != http.StatusUnprocessableEntity {
			t.Fatalf("réglage inconnu : %d", r.status)
		}
		got, _ := a.projects.Get(ctx, o.ID, tenant.AllTeams(), p.Slug)
		want := project.AIExternal
		if forbid {
			want = project.AILocal
		}
		if got.AIMode != want {
			t.Fatalf("réglage %q, attendu %q", got.AIMode, want)
		}
		journal := ab.get("/o/org-a/audit")
		if !strings.Contains(journal.body, "Enrichissement IA du projet") {
			t.Fatal("changement non journalisé")
		}
		// Réglage transmis à l'agent, borné par la politique de l'instance.
		resp := a.api(http.MethodGet, "/api/v1/agent/projects", tok.Plaintext, nil)
		wantMode := `"ai_mode":"external"`
		if forbid {
			wantMode = `"ai_mode":"local"`
		}
		if !strings.Contains(resp.body, wantMode) {
			t.Fatalf("API des agents : %s", resp.body)
		}
	}
}

// TestForgeURLChangeRevokesExternalAI : SEC2-03. L'IA externe est autorisée pour un dépôt
// par un administrateur d'organisation ; un administrateur d'équipe qui fait pointer le
// projet vers un autre dépôt ramène le réglage à « désactivé » (journalisé), l'agent ne
// reçoit donc jamais le nouveau dépôt en « externe ». L'administrateur d'organisation, qui
// peut autoriser l'externe, le garde en changeant de dépôt.
func TestForgeURLChangeRevokesExternalAI(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	admin := a.user("admin@example.org", false)
	lead := a.user("lead@example.org", false)
	o := a.org("org-a", admin)
	a.addTeamMember(o, lead, tenant.TeamAdmin)
	ag, tok, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, nil, "forge", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.projects.Create(ctx, audit.System, o.ID, a.inTeam(o.ID, project.Input{
		Kind: project.KindRepo, Name: "App", ForgeURL: "https://forge.test/acme/app", Branches: []string{"main"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.projects.AssignAgent(ctx, audit.System, o.ID, p.Slug, &ag.ID); err != nil {
		t.Fatal(err)
	}
	ab, lb := a.signIn(admin), a.signIn(lead)
	settings := func(b *browser, forge string) {
		t.Helper()
		if r := b.post("/o/org-a/projects/"+p.Slug+"/settings", url.Values{"name": {"App"}, "forge_url": {forge}, "branches": {"main"}}); r.status != http.StatusSeeOther {
			t.Fatalf("modification vers %s : %d", forge, r.status)
		}
	}
	agentView := func() string { return a.api(http.MethodGet, "/api/v1/agent/projects", tok.Plaintext, nil).body }
	if r := ab.post("/o/org-a/projects/"+p.Slug+"/ai", url.Values{"ai_mode": {"external"}}); r.status != http.StatusSeeOther {
		t.Fatalf("externe par l'administrateur : %d", r.status)
	}

	// L'administrateur d'organisation change de dépôt : réglage gardé.
	settings(ab, "https://forge.test/acme/app2")
	if body := agentView(); !strings.Contains(body, `"ai_mode":"external"`) {
		t.Fatalf("après le changement par l'administrateur : %s", body)
	}
	// Le chef d'équipe, sans changer de dépôt : réglage gardé.
	settings(lb, "https://forge.test/acme/app2")
	if body := agentView(); !strings.Contains(body, `"ai_mode":"external"`) {
		t.Fatalf("modification sans changement de dépôt : %s", body)
	}
	// Le chef d'équipe change de dépôt : réglage ramené à « désactivé ».
	settings(lb, "https://forge.test/acme/secret-payroll")
	body := agentView()
	if !strings.Contains(body, "secret-payroll") || strings.Contains(body, `"ai_mode":"external"`) || !strings.Contains(body, `"ai_mode":"disabled"`) {
		t.Fatalf("après le changement de dépôt par le chef d'équipe : %s", body)
	}
	var reasons int
	if err := a.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = $1 AND details->>'reason' = 'forge_url_changed'`,
			string(audit.ProjectAIModeChanged)).Scan(&reasons)
	}, db.ReadOnly()); err != nil {
		t.Fatal(err)
	}
	if reasons != 1 {
		t.Fatalf("journal du retrait de l'IA externe : %d", reasons)
	}
}
