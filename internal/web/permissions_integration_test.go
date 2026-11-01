//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

func agentEnrollment() agent.EnrollmentInput {
	return agent.EnrollmentInput{Name: "parc", LifetimeHours: 24, MaxUses: 1}
}

// withRouteStub remplace les gestionnaires des routes de l'organisation par un 204,
// derrière leur garde de droit.
func withRouteStub(o *RouterOptions) {
	o.Identity.routeStub = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
}

// expectedStatus dérive de la matrice la réponse d'une route pour un sujet : 404 si la
// ressource est d'une équipe qu'il ne voit pas, 403 si la permission lui manque, 204 (le
// gestionnaire remplacé) sinon.
func expectedStatus(rt orgRoute, s tenant.Subject) int {
	visible := s.Role == tenant.RoleAdmin || s.Team != tenant.TeamNone
	switch rt.target {
	case targetOrg:
		visible = true
	case targetAnyTeam:
		visible = true
	}
	if !visible {
		return http.StatusNotFound
	}
	if tenant.Allowed(s, rt.perm) {
		return http.StatusNoContent
	}
	return http.StatusForbidden
}

// TestRoutePermissionsFollowMatrix est le test des droits dérivé de la matrice : chaque
// route de la table orgRoutes, demandée par chaque sujet de la matrice (administrateur
// d'organisation, administrateur d'équipe, analyste, lecteur, membre hors de l'équipe)
// sur une ressource de l'équipe, répond ce que tenant.Allowed prévoit. La table est aussi
// celle du routeur réel : toute route de /o/{slug} y figure.
func TestRoutePermissionsFollowMatrix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t, withRouteStub)
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	team := a.defaultTeam(o.ID)

	users := map[tenant.Subject]user{{Role: tenant.RoleAdmin}: admin}
	for _, s := range tenant.Subjects() {
		if s.Role == tenant.RoleAdmin {
			continue
		}
		u := a.user(string(s.Team)+"x@example.org", false)
		if s.Team == tenant.TeamNone {
			a.addMember(o, u, tenant.RoleMember)
		} else {
			a.addTeamMember(o, u, s.Team)
		}
		users[s] = u
	}
	victim := a.user("victim@example.org", false)
	a.addTeamMember(o, victim, tenant.TeamReader)
	p, err := a.projects.Create(ctx, audit.System, o.ID, project.Input{Kind: project.KindRepo, Name: "Portail",
		Branches: []string{"main"}, TeamID: team})
	if err != nil {
		t.Fatal(err)
	}
	ag, _, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, &team, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.agents.Get(ctx, o.ID, tenant.AllTeams(), ag.ID)
	if err != nil || len(full.Tokens) != 1 {
		t.Fatalf("jeton de l'agent : %v", err)
	}
	enr, _, err := a.agents.CreateEnrollment(ctx, audit.System, o.ID, a.enrollTeam(o.ID, agentEnrollment()))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.orgs.Invite(ctx, audit.System, o.ID, "invite@example.org", tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	invitations, err := a.orgs.Invitations(ctx, o.ID)
	if err != nil || len(invitations) != 1 {
		t.Fatalf("invitation : %v", err)
	}
	params := func(pattern string) map[string]string {
		token := full.Tokens[0].ID.String()
		if strings.HasPrefix(pattern, "/enrollment-tokens") {
			token = enr.ID.String()
		}
		return map[string]string{"slug": o.Slug, "project": p.Slug, "agentID": ag.ID.String(), "tokenID": token,
			"teamID": team.String(), "userID": itoa(victim.ID), "invitationID": invitations[0].ID.String(),
			"snapshotID": uuid.Nil.String(), "componentID": uuid.Nil.String(), "vulnID": "CVE-2021-44228"}
	}

	browsers := map[tenant.Subject]*browser{}
	for s, u := range users {
		browsers[s] = a.signIn(u)
	}
	routes := orgRoutes(nil)
	for _, rt := range routes {
		for _, s := range tenant.Subjects() {
			path := fill("/o/{slug}"+strings.TrimSuffix(rt.pattern, "/"), params(rt.pattern))
			var got page
			if rt.method == http.MethodGet {
				got = browsers[s].get(path)
			} else {
				got = browsers[s].post(path, url.Values{})
			}
			if want := expectedStatus(rt, s); got.status != want {
				t.Errorf("%s %s pour %+v : %d, attendu %d (%s)", rt.method, rt.pattern, s, got.status, want, rt.perm)
			}
		}
	}

	// Un agent d'organisation (sans équipe) n'existe que pour l'administrateur
	// d'organisation.
	orgAgent, _, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, nil, "ci-org", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	for s, b := range browsers {
		want := http.StatusNotFound
		if s.Role == tenant.RoleAdmin {
			want = http.StatusNoContent
		}
		if got := b.get("/o/org-a/agents/" + orgAgent.ID.String()); got.status != want {
			t.Errorf("agent d'organisation pour %+v : %d, attendu %d", s, got.status, want)
		}
	}

	// La table est celle du routeur réel.
	var mounted []string
	for _, r := range a.routes() {
		if rest, ok := strings.CutPrefix(r.pattern, "/o/{slug}"); ok {
			if rest == "" {
				rest = "/"
			}
			mounted = append(mounted, r.method+" "+rest)
		}
	}
	var declared []string
	for _, rt := range routes {
		declared = append(declared, rt.method+" "+rt.pattern)
	}
	slices.Sort(mounted)
	slices.Sort(declared)
	if !slices.Equal(mounted, declared) {
		t.Fatalf("routes montées %v\ndéclarées %v", mounted, declared)
	}
}
