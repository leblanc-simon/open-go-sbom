package tenant

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

var update = flag.Bool("update", false, "régénère docs/security/permissions.md")

func TestRoleOrder(t *testing.T) {
	cases := []struct {
		role, min Role
		want      bool
	}{
		{RoleAdmin, RoleMember, true}, {RoleAdmin, RoleAdmin, true}, {RoleMember, RoleMember, true},
		{RoleMember, RoleAdmin, false}, {"chef", RoleMember, false}, {"viewer", RoleMember, false},
	}
	for _, c := range cases {
		if got := c.role.AtLeast(c.min); got != c.want {
			t.Errorf("%s ≥ %s : %v", c.role, c.min, got)
		}
	}
	for _, r := range Roles() {
		if got, err := ParseRole(string(r)); err != nil || got != r {
			t.Errorf("%s : %v", r, err)
		}
	}
	for _, s := range []string{"chef", "viewer", "analyst", ""} {
		if _, err := ParseRole(s); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("%q : %v", s, err)
		}
	}
}

func TestTeamRoleOrder(t *testing.T) {
	cases := []struct {
		role, min TeamRole
		want      bool
	}{
		{TeamAdmin, TeamReader, true}, {TeamAnalyst, TeamReader, true}, {TeamReader, TeamAnalyst, false},
		{TeamAnalyst, TeamAdmin, false}, {TeamNone, TeamReader, false}, {"chef", TeamReader, false},
	}
	for _, c := range cases {
		if got := c.role.AtLeast(c.min); got != c.want {
			t.Errorf("%s ≥ %s : %v", c.role, c.min, got)
		}
	}
	for _, r := range TeamRoles() {
		if got, err := ParseTeamRole(string(r)); err != nil || got != r {
			t.Errorf("%s : %v", r, err)
		}
	}
	if _, err := ParseTeamRole(""); !errors.Is(err, ErrInvalidRole) {
		t.Fatal(err)
	}
}

func TestAccessContext(t *testing.T) {
	if _, ok := AccessFrom(context.Background()); ok {
		t.Fatal("accès dans un contexte vide")
	}
	org, _ := NewOrgID()
	ctx := WithAccess(context.Background(), Access{Org: org, Slug: "a", Role: RoleMember})
	a, ok := AccessFrom(ctx)
	if !ok || a.Slug != "a" {
		t.Fatalf("%+v", a)
	}
	if got, ok := FromContext(ctx); !ok || got != org {
		t.Fatal("organisation absente du contexte")
	}
}

// TestMatrixRules nomme les règles de la matrice décidées le 1er novembre 2026.
func TestMatrixRules(t *testing.T) {
	admin := Subject{Role: RoleAdmin}
	outside := Subject{Role: RoleMember}
	reader := Subject{Role: RoleMember, Team: TeamReader}
	analyst := Subject{Role: RoleMember, Team: TeamAnalyst}
	teamAdmin := Subject{Role: RoleMember, Team: TeamAdmin}
	for _, r := range Matrix() {
		if !Allowed(admin, r.Permission) {
			t.Errorf("l'administrateur d'organisation n'a pas %s", r.Permission)
		}
		if r.Scope == ScopeTeam && Allowed(outside, r.Permission) {
			t.Errorf("un membre hors de l'équipe a %s", r.Permission)
		}
		if r.Description == "" {
			t.Errorf("%s sans description", r.Permission)
		}
	}
	checks := []struct {
		s    Subject
		p    Permission
		want bool
	}{
		{reader, PermProjectView, true}, {reader, PermProjectScan, false}, {reader, PermFindingTriage, false},
		{analyst, PermFindingTriage, true}, {analyst, PermProjectScan, true}, {analyst, PermProjectManage, false},
		{teamAdmin, PermProjectManage, true}, {teamAdmin, PermAgentManage, true}, {teamAdmin, PermTeamMembers, true},
		{teamAdmin, PermTeamsManage, false}, {teamAdmin, PermMembersManage, false}, {teamAdmin, PermOrgManage, false},
		{outside, PermOrgView, true}, {outside, PermMembersView, true}, {outside, PermProjectView, false},
		{Subject{Role: "viewer", Team: TeamAdmin}, PermProjectView, false},
		{admin, "inconnue", false},
	}
	for _, c := range checks {
		if got := Allowed(c.s, c.p); got != c.want {
			t.Errorf("%+v %s : %v, attendu %v", c.s, c.p, got, c.want)
		}
	}
}

func TestAccessCanAndVisibility(t *testing.T) {
	org, _ := NewOrgID()
	ta, tb, tc := uuid.New(), uuid.New(), uuid.New()
	a := Access{Org: org, Role: RoleMember, Teams: map[uuid.UUID]TeamRole{ta: TeamReader, tb: TeamAdmin}}
	if !a.Can(PermProjectView, ta) || a.Can(PermProjectManage, ta) || !a.Can(PermProjectManage, tb) || a.Can(PermProjectView, tc) {
		t.Fatal("droits par équipe")
	}
	if a.Can(PermAgentView, uuid.Nil) {
		t.Fatal("un membre voit un agent d'organisation")
	}
	v := a.Visibility()
	if v.All() || !v.Sees(ta) || !v.Sees(tb) || v.Sees(tc) || len(v.Teams()) != 2 {
		t.Fatalf("visibilité %+v", v)
	}
	if got := a.TeamsWith(PermProjectCreate); len(got) != 1 || got[0] != tb {
		t.Fatalf("équipes où créer : %v", got)
	}
	if !a.CanAny(PermProjectCreate) || a.CanAny(PermTeamsManage) {
		t.Fatal("CanAny")
	}
	none := Access{Org: org, Role: RoleMember}
	if none.Visibility().Sees(ta) || none.Visibility().Setting() != "{}" {
		t.Fatal("un membre sans équipe voit des projets")
	}
	admin := Access{Org: org, Role: RoleAdmin}
	if !admin.Visibility().All() || admin.Visibility().Setting() != "*" || !admin.Can(PermAgentManage, uuid.Nil) {
		t.Fatal("administrateur")
	}
	if (Access{}).Can(PermOrgView, uuid.Nil) || (Visibility{}).Sees(ta) || (Access{}).Visibility().All() {
		t.Fatal("valeurs zéro")
	}
	if got := OnlyTeams(tb, ta, ta).Setting(); got != OnlyTeams(ta, tb).Setting() {
		t.Fatalf("réglage non canonique : %s", got)
	}
}

// TestPermissionsDocument vérifie que docs/security/permissions.md est la sortie exacte de
// la matrice (-update le régénère).
func TestPermissionsDocument(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "security", "permissions.md")
	want := PermissionsDocument()
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s n'est pas à jour : go test ./internal/tenant -run TestPermissionsDocument -update", path)
	}
}
