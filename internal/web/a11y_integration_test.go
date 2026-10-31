//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/internal/web/webtest"
)

var titlePattern = regexp.MustCompile(`<title>([^<]*)</title>`)

// pageTitle renvoie le titre de la page, entités décodées.
func pageTitle(t *testing.T, body string) string {
	t.Helper()
	m := titlePattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("page sans <title>")
	}
	return unescape(m[1])
}

// assertScreen vérifie une page rendue : accessibilité automatique, absence de code en
// ligne, paramètres de traduction présents.
func assertScreen(t *testing.T, name string, p page) {
	t.Helper()
	if strings.Contains(p.body, "<no value>") {
		t.Errorf("%s : paramètre de traduction manquant", name)
	}
	for _, problem := range webtest.CheckAccessibility([]byte(p.body)) {
		t.Errorf("%s : %s", name, problem)
	}
	for _, problem := range webtest.CheckNoInlineCode([]byte(p.body)) {
		t.Errorf("%s : %s", name, problem)
	}
}

// TestIrreversibleActionsAreConfirmed (RGAA 11.12) : chaque action irréversible est un
// lien vers une page de confirmation (GET sans effet, qui nomme l'objet et les
// conséquences), dont le formulaire POST exécute l'action ; « Annuler » ramène à l'écran
// d'origine.
func TestIrreversibleActionsAreConfirmed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	member := a.user("membre@example.org", false)
	o := a.org("atelier", admin)
	a.addMember(o, member, tenant.RoleViewer)
	ag, _, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, "ci-principal", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	if ag, err = a.agents.Get(ctx, o.ID, ag.ID); err != nil {
		t.Fatal(err)
	}
	enr, _, err := a.agents.CreateEnrollment(ctx, audit.System, o.ID, agent.EnrollmentInput{Name: "Serveurs web", LifetimeHours: 24, MaxUses: 3})
	if err != nil {
		t.Fatal(err)
	}
	pat, _, err := a.accounts.CreatePersonalToken(ctx, audit.System, admin.ID, "Export CI", 30)
	if err != nil {
		t.Fatal(err)
	}
	job := a.deadJob("ingest.decode", o.ID.String())
	b := a.signIn(admin)

	agentPath := "/o/atelier/agents/" + ag.ID.String()
	cases := []struct {
		name, list, action, cancel string
		want                       []string // textes de la page de confirmation
		form                       url.Values
		done                       string // redirection attendue après le POST (ou statut 200 : page rendue)
		applied                    func() bool
	}{
		{"jeton d'agent", agentPath, agentPath + "/tokens/" + ag.Tokens[0].ID.String() + "/revoke", agentPath,
			[]string{"Révoquer le jeton « initial » de l'agent ci-principal ?", "Cette action est définitive", "Révoquer le jeton « initial »"},
			nil, "token_revoked", func() bool {
				got, err := a.agents.Get(ctx, o.ID, ag.ID)
				return err == nil && got.Tokens[0].RevokedAt != nil
			}},
		{"jeton d'inscription", "/o/atelier/agents", "/o/atelier/enrollment-tokens/" + enr.ID.String() + "/revoke", "/o/atelier/agents",
			[]string{"Révoquer le jeton d'inscription « Serveurs web » ?", "Les agents déjà inscrits"}, nil, "enrollment_revoked", func() bool {
				list, err := a.agents.Enrollments(ctx, o.ID)
				return err == nil && len(list) == 1 && list[0].RevokedAt != nil
			}},
		{"désactivation d'agent", agentPath, agentPath + "/disable", agentPath,
			[]string{"Désactiver l'agent ci-principal ?", "ne se réactive pas", "Désactiver l'agent"}, nil, "agent_disabled", func() bool {
				got, err := a.agents.Get(ctx, o.ID, ag.ID)
				return err == nil && got.DisabledAt != nil
			}},
		{"retrait d'un membre", "/o/atelier/members", "/o/atelier/members/" + itoa(member.ID) + "/remove", "/o/atelier/members",
			[]string{"Retirer membre@example.org de l'organisation ?", "perdra aussitôt l'accès à Org atelier", "Retirer membre@example.org"},
			nil, "member_removed", func() bool {
				_, err := a.orgs.Member(ctx, o.ID, member.ID)
				return err != nil
			}},
		{"jeton personnel", "/account/tokens", "/account/tokens/" + pat.ID.String() + "/revoke", "/account/tokens",
			[]string{"Révoquer le jeton « Export CI » ?", pat.Prefix() + "…"}, nil, "personal_token_revoked", func() bool {
				list, err := a.accounts.PersonalTokens(ctx, admin.ID)
				return err == nil && len(list) == 1 && list[0].RevokedAt != nil
			}},
		{"réinitialisation du mot de passe", "/admin/users/" + itoa(member.ID), "/admin/users/" + itoa(member.ID) + "/reset-password", "/admin/users/" + itoa(member.ID),
			[]string{"Réinitialiser le mot de passe de membre@example.org ?", "affiché une seule fois"}, nil, "", func() bool {
				got, err := a.accounts.Get(ctx, member.ID)
				return err == nil && got.MustChangePwd
			}},
		{"réinitialisation du TOTP", "/admin/users/" + itoa(member.ID), "/admin/users/" + itoa(member.ID) + "/reset-totp", "/admin/users/" + itoa(member.ID),
			[]string{"Réinitialiser le TOTP de membre@example.org ?", "configurera un nouveau TOTP", "mot de passe temporaire"}, nil, "", func() bool {
				return a.countRows(`SELECT count(*) FROM mfa_totp WHERE user_id = $1 AND enabled = 1`, member.ID) == 0
			}},
		{"abandon d'un traitement", "/admin/jobs", "/admin/jobs/" + job.String() + "/discard", "/admin/jobs",
			[]string{"Abandonner le traitement ingest.decode ?", "tentatives : 10"}, nil, "job_discarded", func() bool {
				return a.jobStatus(job) == "absent"
			}},
	}
	for _, c := range cases {
		list := b.get(c.list)
		if list.status != http.StatusOK || !strings.Contains(list.body, `href="`+c.action+`"`) {
			t.Errorf("%s : %s ne mène pas à la confirmation (%d)", c.name, c.list, list.status)
		}
		if strings.Contains(list.body, `action="`+c.action+`"`) {
			t.Errorf("%s : %s agit encore en un clic", c.name, c.list)
		}
		for _, lang := range []string{"fr", "en"} {
			p := b.get(c.action + "?lang=" + lang)
			if p.status != http.StatusOK {
				t.Fatalf("%s : confirmation %d", c.name, p.status)
			}
			assertScreen(t, c.name+" ("+lang+")", p)
			body := unescape(p.body)
			if lang == "fr" {
				for _, want := range c.want {
					if !strings.Contains(body, want) {
						t.Errorf("%s : « %s » absent de la confirmation", c.name, want)
					}
				}
			}
			if !strings.Contains(p.body, `action="`+c.action+`"`) || !strings.Contains(p.body, `href="`+c.cancel+`"`) {
				t.Errorf("%s : formulaire ou lien d'annulation absent", c.name)
			}
		}
		if c.applied() {
			t.Fatalf("%s : la page de confirmation a agi", c.name)
		}
		p := b.post(c.action, c.form)
		switch {
		case c.done == "" && p.status == http.StatusOK:
		case c.done != "" && p.status == http.StatusSeeOther && strings.Contains(p.location, "done="+c.done):
		default:
			t.Fatalf("%s : POST %d %q", c.name, p.status, p.location)
		}
		if !c.applied() {
			t.Fatalf("%s : action non appliquée", c.name)
		}
	}

	// Objet déjà révoqué ou désactivé : rien à confirmer, retour à l'écran.
	for _, path := range []string{agentPath + "/tokens/" + ag.Tokens[0].ID.String() + "/revoke", agentPath + "/disable",
		"/o/atelier/enrollment-tokens/" + enr.ID.String() + "/revoke", "/account/tokens/" + pat.ID.String() + "/revoke"} {
		if p := b.get(path); p.status != http.StatusSeeOther {
			t.Errorf("%s déjà appliqué : %d", path, p.status)
		}
	}
	// Abandonné entre-temps : l'écran des traitements le dit.
	if p := b.get("/admin/jobs/" + job.String() + "/discard"); p.status != http.StatusNotFound || !strings.Contains(unescape(p.body), "déjà") {
		t.Errorf("traitement déjà abandonné : %d", p.status)
	}
	// Jeton personnel d'un autre compte, membre inconnu, action sans confirmation.
	otherPAT, _, err := a.accounts.CreatePersonalToken(ctx, audit.System, member.ID, "Autre", 30)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/account/tokens/" + otherPAT.ID.String() + "/revoke", "/account/tokens/x/revoke",
		"/o/atelier/members/999999/remove", "/o/atelier/members/x/remove", "/admin/users/" + itoa(member.ID) + "/deactivate",
		"/admin/users/999999/reset-totp", "/admin/jobs/x/discard", agentPath + "/tokens/0192d6a4-0000-7000-8000-000000000002/revoke",
		"/o/atelier/enrollment-tokens/0192d6a4-0000-7000-8000-000000000002/revoke"} {
		if p := b.get(path); p.status != http.StatusNotFound {
			t.Errorf("GET %s : %d, attendu 404", path, p.status)
		}
	}

	// Son propre retrait : la page prévient qu'on perd l'accès.
	second := a.user("second@example.org", false)
	a.addMember(o, second, tenant.RoleAdmin)
	s := a.signIn(second)
	if body := unescape(s.get("/o/atelier/members/" + itoa(second.ID) + "/remove").body); !strings.Contains(body, "Vous vous retirez vous-même") {
		t.Error("retrait de soi-même : avertissement absent")
	}
}

// TestPageTitlesAreDistinct (RGAA 8.6) : le titre nomme l'écran et l'organisation, la
// requête d'une recherche, et commence par « Erreur » quand un formulaire est refusé.
func TestPageTitlesAreDistinct(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	a.org("nord", admin)
	a.org("sud", admin)
	b := a.signIn(admin)

	seen := map[string]string{}
	for _, slug := range []string{"nord", "sud"} {
		for _, path := range []string{"", "/projects", "/projects/new", "/search", "/search?q=log4j-core", "/agents", "/agents/new",
			"/enrollment-tokens/new", "/members", "/settings", "/audit"} {
			p := b.get("/o/" + slug + path)
			if p.status != http.StatusOK {
				t.Fatalf("/o/%s%s : %d", slug, path, p.status)
			}
			title := pageTitle(t, p.body)
			if !strings.Contains(title, "Org "+slug) {
				t.Errorf("/o/%s%s : titre %q sans l'organisation", slug, path, title)
			}
			if other, dup := seen[title]; dup {
				t.Errorf("titre %q partagé par %s et /o/%s%s", title, other, slug, path)
			}
			seen[title] = "/o/" + slug + path
		}
	}
	for _, path := range []string{"/account", "/account/password", "/account/tokens", "/sitemap", "/admin/users", "/admin/orgs",
		"/admin/vulndb", "/admin/jobs", "/admin/audit"} {
		title := pageTitle(t, b.get(path).body)
		if other, dup := seen[title]; dup {
			t.Errorf("titre %q partagé par %s et %s", title, other, path)
		}
		seen[title] = path
	}
	if got := pageTitle(t, b.get("/o/nord/search?q=log4j-core").body); got != "Recherche « log4j-core » — Org nord · open-go-sbom" {
		t.Errorf("titre de recherche : %q", got)
	}
	if got := pageTitle(t, b.get("/o/nord?lang=en").body); got != "Dashboard — Org nord · open-go-sbom" {
		t.Errorf("titre du tableau de bord : %q", got)
	}
	// Formulaire refusé : le titre le dit, en français et en anglais.
	p := b.post("/o/nord/projects", url.Values{"kind": {"repo"}, "name": {""}})
	if p.status != http.StatusUnprocessableEntity || !strings.HasPrefix(pageTitle(t, p.body), "Erreur : ") {
		t.Errorf("formulaire refusé : %d %q", p.status, pageTitle(t, p.body))
	}
	if p := b.post("/admin/users?lang=en", url.Values{"email": {"x"}}); !strings.HasPrefix(pageTitle(t, p.body), "Error: ") {
		t.Errorf("formulaire refusé (en) : %d %q", p.status, pageTitle(t, p.body))
	}
	// Une page d'erreur garde son propre titre.
	if got := pageTitle(t, b.get("/o/nord/projects/absent").body); strings.HasPrefix(got, "Erreur") {
		t.Errorf("page 404 : %q", got)
	}
}

// TestSiteMap (RGAA 12.1) : second système de navigation, lié du pied de chaque page
// authentifiée ; il reprend les rubriques que le rôle de chaque organisation ouvre.
func TestSiteMap(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	viewer := a.user("lecteur@example.org", false)
	o := a.org("nord", admin)
	a.org("sud", admin)
	a.addMember(o, viewer, tenant.RoleViewer)

	b := a.signIn(admin)
	for _, lang := range []string{"fr", "en"} {
		p := b.get("/sitemap?lang=" + lang)
		if p.status != http.StatusOK {
			t.Fatalf("plan du site : %d", p.status)
		}
		assertScreen(t, "plan du site ("+lang+")", p)
	}
	body := unescape(b.get("/sitemap").body)
	for _, want := range []string{"Organisation Org nord", "Organisation Org sud", `href="/o/nord/settings"`, `href="/o/sud/audit"`,
		`href="/account/tokens"`, "Administration de l'instance", `href="/admin/jobs"`} {
		if !strings.Contains(body, want) {
			t.Errorf("plan du site : %q absent", want)
		}
	}
	if !strings.Contains(b.get("/o/nord/projects").body, `href="/sitemap"`) {
		t.Error("pied de page sans lien vers le plan du site")
	}

	v := a.signIn(viewer)
	body = unescape(v.get("/sitemap").body)
	if !strings.Contains(body, `href="/o/nord/projects"`) || strings.Contains(body, "/o/nord/settings") ||
		strings.Contains(body, "/o/sud") || strings.Contains(body, "/admin") {
		t.Error("plan du site d'un lecteur : rubriques hors de ses droits")
	}
	if strings.Contains(a.browser().get("/login").body, `href="/sitemap"`) {
		t.Error("lien vers le plan du site sur la page de connexion")
	}
}
