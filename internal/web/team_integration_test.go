//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

var teamHref = regexp.MustCompile(`/o/org-a/teams/([0-9a-f-]{36})`)

// TestTeamScreens : écrans des équipes et des invitations (deux langues, accessibilité,
// CSP), création, membres, rôle, rattachement d'un projet, suppression, chaque geste
// journalisé ; un administrateur d'équipe gère son équipe sans gérer l'organisation.
func TestTeamScreens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin, lead, bob := a.user("admin@example.org", false), a.user("lead@example.org", false), a.user("bob@example.org", false)
	o := a.org("org-a", admin)
	a.addMember(o, lead, tenant.RoleMember)
	a.addMember(o, bob, tenant.RoleMember)
	p, err := a.projects.Create(ctx, audit.System, o.ID, a.inTeam(o.ID, project.Input{Kind: project.KindRepo, Name: "Portail",
		Branches: []string{"main"}}))
	if err != nil {
		t.Fatal(err)
	}
	ad := a.signIn(admin)

	created := ad.post("/o/org-a/teams", url.Values{"name": {"Plateforme"}})
	if created.status != http.StatusSeeOther || !strings.Contains(created.location, "team_created") {
		t.Fatalf("création : %d %q %s", created.status, created.location, created.body)
	}
	m := teamHref.FindStringSubmatch(created.location)
	if m == nil {
		t.Fatalf("équipe créée : %q", created.location)
	}
	teamPath := "/o/org-a/teams/" + m[1]
	if p := ad.post("/o/org-a/teams", url.Values{"name": {"plateforme"}}); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(unescape(p.body), "Une équipe porte déjà ce nom") {
		t.Errorf("nom pris : %d", p.status)
	}
	steps := []struct {
		path string
		form url.Values
		done string
	}{
		{teamPath + "/members", url.Values{"email": {lead.Email}, "role": {"admin"}}, "team_member_added"},
		{teamPath + "/members", url.Values{"email": {bob.Email}, "role": {"reader"}}, "team_member_added"},
		{teamPath + "/members/" + itoa(bob.ID) + "/role", url.Values{"role": {"analyst"}}, "team_member_updated"},
		{teamPath, url.Values{"name": {"Plateforme web"}}, "team_renamed"},
	}
	for _, s := range steps {
		if p := ad.post(s.path, s.form); p.status != http.StatusSeeOther || !strings.Contains(p.location, s.done) {
			t.Fatalf("%s : %d %q\n%s", s.path, p.status, p.location, p.body)
		}
	}
	if p := ad.post(teamPath+"/members", url.Values{"email": {"absent@example.org"}, "role": {"reader"}}); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(unescape(p.body), "invitez d'abord le compte") {
		t.Errorf("compte hors de l'organisation : %d", p.status)
	}

	// L'administrateur de l'équipe y rattache le projet (droit dans les deux équipes : il
	// est aussi administrateur de « Général »), puis gère ses membres ; il ne gère ni les
	// équipes ni les membres de l'organisation.
	if err := a.orgs.AddTeamMember(ctx, audit.System, o.ID, a.defaultTeam(o.ID), lead.Email, tenant.TeamAdmin); err != nil {
		t.Fatal(err)
	}
	ld := a.signIn(lead)
	settings := ld.get("/o/org-a/projects/" + p.Slug + "/settings")
	if settings.status != http.StatusOK || !strings.Contains(settings.body, `action="/o/org-a/projects/`+p.Slug+`/team"`) {
		t.Fatalf("paramètres du projet : %d", settings.status)
	}
	webtest.AssertAccessible(t, []byte(settings.body))
	if p := ld.post("/o/org-a/projects/"+p.Slug+"/team", url.Values{"team": {m[1]}}); p.status != http.StatusSeeOther ||
		!strings.Contains(p.location, "project_team_changed") {
		t.Fatalf("rattachement : %d %q", p.status, p.location)
	}
	if got, err := a.projects.Get(ctx, o.ID, tenant.AllTeams(), p.Slug); err != nil || got.TeamName != "Plateforme web" {
		t.Fatalf("équipe du projet : %+v, %v", got, err)
	}
	if p := ld.post("/o/org-a/projects/"+p.Slug+"/team", url.Values{"team": {"not-a-team"}}); p.status != http.StatusUnprocessableEntity {
		t.Errorf("équipe illisible : %d", p.status)
	}
	if p := ld.post("/o/org-a/teams", url.Values{"name": {"X"}}); p.status != http.StatusForbidden {
		t.Errorf("création d'équipe par un administrateur d'équipe : %d", p.status)
	}
	if p := ld.post("/o/org-a/members", url.Values{"email": {"x@example.org"}, "role": {"member"}}); p.status != http.StatusForbidden {
		t.Errorf("invitation par un administrateur d'équipe : %d", p.status)
	}
	// Le formulaire d'un nouveau projet ne propose que ses équipes administrées.
	newForm := ld.get("/o/org-a/projects/new")
	if newForm.status != http.StatusOK || !strings.Contains(newForm.body, "Plateforme web") {
		t.Errorf("nouveau projet : %d", newForm.status)
	}

	// Écrans, en deux langues : accessibles et sans code en ligne.
	for _, lang := range []string{"fr", "en"} {
		for _, path := range []string{"/o/org-a/teams", teamPath, "/o/org-a/members", "/o/org-a/projects", "/o/org-a/projects/new",
			"/o/org-a/agents/new", "/o/org-a/enrollment-tokens/new", "/account/invitations", teamPath + "/delete",
			teamPath + "/members/" + itoa(bob.ID) + "/remove"} {
			pg := ad.get(path + "?lang=" + lang)
			if pg.status != http.StatusOK {
				t.Errorf("%s (%s) : %d", path, lang, pg.status)
				continue
			}
			webtest.AssertAccessible(t, []byte(pg.body))
			webtest.AssertNoInlineCode(t, []byte(pg.body))
		}
	}
	// Une équipe qui a encore un projet ne se supprime pas ; vide, elle se supprime.
	if p := ad.post(teamPath+"/delete", nil); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(unescape(p.body), "Cette équipe a encore des projets") {
		t.Errorf("suppression d'une équipe avec projet : %d", p.status)
	}
	if p := ad.post(teamPath+"/members/"+itoa(bob.ID)+"/remove", nil); p.status != http.StatusSeeOther {
		t.Errorf("retrait d'un membre : %d", p.status)
	}
	if err := a.projects.SetTeam(ctx, audit.System, o.ID, p.Slug, a.defaultTeam(o.ID)); err != nil {
		t.Fatal(err)
	}
	if p := ad.post(teamPath+"/delete", nil); p.status != http.StatusSeeOther || !strings.Contains(p.location, "team_deleted") {
		t.Errorf("suppression : %d %q", p.status, p.location)
	}
	journal := unescape(ad.get("/o/org-a/audit").body)
	for _, want := range []string{"Équipe Plateforme créée", "lead@example.org ajouté à l'équipe Plateforme avec le rôle admin",
		"Rôle de bob@example.org dans l'équipe Plateforme : reader → analyst", "Équipe renommée de « Plateforme » en « Plateforme web »",
		"Projet portail rattaché à l'équipe Plateforme web (auparavant Général)", "bob@example.org retiré de l'équipe Plateforme web",
		"Équipe Plateforme web supprimée"} {
		if !strings.Contains(journal, want) {
			t.Errorf("journal sans « %s »", want)
		}
	}
}

// TestInvitationScreens : l'invité voit l'invitation, la décline après confirmation ;
// l'administrateur révoque une invitation après confirmation.
func TestInvitationScreens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin, bob := a.user("admin@example.org", false), a.user("bob@example.org", false)
	o := a.org("org-a", admin)
	for _, email := range []string{bob.Email, "absent@example.org"} {
		if err := a.orgs.Invite(ctx, audit.System, o.ID, email, tenant.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	b := a.signIn(bob)
	home := b.get("/")
	if home.status != http.StatusOK || !strings.Contains(home.body, `href="/account/invitations"`) {
		t.Errorf("accueil sans organisation : %d", home.status)
	}
	list := b.get("/account/invitations")
	webtest.AssertAccessible(t, []byte(list.body))
	webtest.AssertNoInlineCode(t, []byte(list.body))
	m := regexp.MustCompile(`/account/invitations/([0-9a-f-]{36})/decline`).FindStringSubmatch(list.body)
	if m == nil || !strings.Contains(list.body, "Org org-a") {
		t.Fatalf("invitation absente :\n%s", list.body)
	}
	confirm := b.get(m[0])
	if confirm.status != http.StatusOK || !strings.Contains(unescape(confirm.body), "Décliner l'invitation de Org org-a ?") {
		t.Fatalf("confirmation du refus : %d", confirm.status)
	}
	webtest.AssertAccessible(t, []byte(confirm.body))
	if p := b.post(m[0], nil); p.status != http.StatusSeeOther || !strings.Contains(p.location, "invitation_declined") {
		t.Fatalf("refus : %d %q", p.status, p.location)
	}
	if p := b.get(m[0]); p.status != http.StatusNotFound {
		t.Errorf("invitation déclinée encore proposée : %d", p.status)
	}
	// Un autre compte ne peut ni voir ni accepter l'invitation d'autrui.
	invitations, _ := a.orgs.Invitations(ctx, o.ID)
	if len(invitations) != 1 || invitations[0].Email != "absent@example.org" {
		t.Fatalf("invitations restantes : %+v", invitations)
	}
	if p := b.post("/account/invitations/"+invitations[0].ID.String()+"/accept", nil); p.status != http.StatusNotFound {
		t.Errorf("acceptation de l'invitation d'autrui : %d", p.status)
	}
	ad := a.signIn(admin)
	revoke := "/o/org-a/invitations/" + invitations[0].ID.String() + "/revoke"
	if members := ad.get("/o/org-a/members"); !strings.Contains(members.body, `href="`+revoke+`"`) {
		t.Errorf("lien de révocation absent")
	}
	if p := ad.get(revoke); p.status != http.StatusOK || !strings.Contains(unescape(p.body), "Révoquer l'invitation de absent@example.org ?") {
		t.Errorf("confirmation de révocation : %d", p.status)
	}
	if p := ad.post(revoke, nil); p.status != http.StatusSeeOther || !strings.Contains(p.location, "invitation_revoked") {
		t.Errorf("révocation : %d %q", p.status, p.location)
	}
	if p := ad.post(revoke, nil); p.status != http.StatusNotFound {
		t.Errorf("seconde révocation : %d", p.status)
	}
}
