//go:build integration

package org_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/tenant"
)

func (f fixture) actions(t *testing.T, o tenant.OrgID) []audit.Action {
	t.Helper()
	var out []audit.Action
	if err := f.tdb.App.InOrg(context.Background(), o, func(tx *db.OrgTx) error {
		p, err := audit.ListOrg(context.Background(), tx, "", audit.MaxPage)
		for _, e := range p.Items {
			out = append(out, e.Action)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTeamsLifecycleIsAudited : création, renommage, membres et suppression d'une équipe,
// chacun au journal ; contraintes (nom unique, membre de l'organisation, équipe sans
// projet pour la supprimer).
func TestTeamsLifecycleIsAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	admin, bob, outsider := f.user(t, "admin@example.org"), f.user(t, "bob@example.org"), f.user(t, "out@example.org")
	o, err := f.orgs.Create(ctx, audit.System, "atelier", "Atelier", "fr", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	teams, err := f.orgs.Teams(ctx, o.ID, tenant.AllTeams())
	if err != nil || len(teams) != 1 || teams[0].Name != "Général" {
		t.Fatalf("équipe par défaut : %+v, %v", teams, err)
	}
	if err := f.orgs.AddMember(ctx, audit.System, o.ID, bob.Email, tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	web, err := f.orgs.CreateTeam(ctx, audit.System, o.ID, " Web ")
	if err != nil || web.Name != "Web" {
		t.Fatalf("création : %+v, %v", web, err)
	}
	if _, err := f.orgs.CreateTeam(ctx, audit.System, o.ID, "WEB"); !isKey(err, org.KeyTeamNameTaken) {
		t.Fatalf("nom pris : %v", err)
	}
	if _, err := f.orgs.CreateTeam(ctx, audit.System, o.ID, " "); !isKey(err, org.KeyTeamNameInvalid) {
		t.Fatalf("nom vide : %v", err)
	}
	if err := f.orgs.RenameTeam(ctx, audit.System, o.ID, web.ID, "Général"); !isKey(err, org.KeyTeamNameTaken) {
		t.Fatalf("renommage sur un nom pris : %v", err)
	}
	if err := f.orgs.RenameTeam(ctx, audit.System, o.ID, web.ID, "Portail"); err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.AddTeamMember(ctx, audit.System, o.ID, web.ID, outsider.Email, tenant.TeamReader); !isKey(err, org.KeyNotOrgMember) {
		t.Fatalf("compte hors de l'organisation : %v", err)
	}
	if err := f.orgs.AddTeamMember(ctx, audit.System, o.ID, web.ID, bob.Email, "chef"); !isKey(err, org.KeyTeamRoleInvalid) {
		t.Fatalf("rôle inconnu : %v", err)
	}
	if err := f.orgs.AddTeamMember(ctx, audit.System, o.ID, web.ID, bob.Email, tenant.TeamReader); err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.AddTeamMember(ctx, audit.System, o.ID, web.ID, bob.Email, tenant.TeamAdmin); !isKey(err, org.KeyTeamMemberExists) {
		t.Fatalf("doublon : %v", err)
	}
	if err := f.orgs.SetTeamMemberRole(ctx, audit.System, o.ID, web.ID, bob.ID, tenant.TeamAnalyst); err != nil {
		t.Fatal(err)
	}
	acc, err := f.orgs.Access(ctx, "atelier", bob.ID)
	if err != nil || acc.Role != tenant.RoleMember || acc.UserID != bob.ID || acc.TeamRole(web.ID) != tenant.TeamAnalyst ||
		acc.TeamRole(teams[0].ID) != tenant.TeamNone {
		t.Fatalf("accès : %+v, %v", acc, err)
	}
	// Bob ne voit que son équipe.
	visible, err := f.orgs.Teams(ctx, o.ID, acc.Visibility())
	if err != nil || len(visible) != 1 || visible[0].ID != web.ID || visible[0].Members != 1 {
		t.Fatalf("équipes visibles : %+v, %v", visible, err)
	}
	if _, err := f.orgs.Team(ctx, o.ID, acc.Visibility(), teams[0].ID); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("équipe invisible : %v", err)
	}
	if err := f.orgs.RemoveTeamMember(ctx, audit.System, o.ID, web.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.RemoveTeamMember(ctx, audit.System, o.ID, web.ID, bob.ID); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("second retrait : %v", err)
	}
	// Une équipe qui a un projet ne se supprime pas.
	if err := f.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO projects (org_id, id, kind, slug, name, team_id) VALUES ($1, $2, 'repo', 'p', 'p', $3)`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), web.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.DeleteTeam(ctx, audit.System, o.ID, web.ID); !isKey(err, org.KeyTeamHasProjects) {
		t.Fatalf("équipe avec projet : %v", err)
	}
	empty, err := f.orgs.CreateTeam(ctx, audit.System, o.ID, "Vide")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.DeleteTeam(ctx, audit.System, o.ID, empty.ID); err != nil {
		t.Fatal(err)
	}
	got := f.actions(t, o.ID)
	for _, want := range []audit.Action{audit.TeamCreated, audit.TeamRenamed, audit.TeamDeleted, audit.TeamMemberAdded,
		audit.TeamMemberRoleChanged, audit.TeamMemberRemoved} {
		if !slices.Contains(got, want) {
			t.Errorf("journal sans %s : %v", want, got)
		}
	}
}

// TestRemovingAMemberRemovesItsTeams : le retrait de l'organisation retire le compte de
// ses équipes (clé étrangère composite).
func TestRemovingAMemberRemovesItsTeams(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	admin, bob := f.user(t, "admin@example.org"), f.user(t, "bob@example.org")
	o, _ := f.orgs.Create(ctx, audit.System, "o", "O", "fr", admin.ID)
	if err := f.orgs.AddMember(ctx, audit.System, o.ID, bob.Email, tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	teams, _ := f.orgs.Teams(ctx, o.ID, tenant.AllTeams())
	if err := f.orgs.AddTeamMember(ctx, audit.System, o.ID, teams[0].ID, bob.Email, tenant.TeamAdmin); err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.RemoveMember(ctx, audit.System, o.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.orgs.TeamMember(ctx, o.ID, teams[0].ID, bob.ID); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("membre d'équipe après retrait de l'organisation : %v", err)
	}
	// Un compte hors de l'organisation ne peut pas être inséré dans une équipe, même en SQL.
	err := f.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO team_members (org_id, team_id, user_id, role) VALUES ($1, $2, $3, 'reader')`,
			tx.OrgID(), teams[0].ID, bob.ID)
		return err
	})
	if err == nil {
		t.Fatal("membre d'équipe hors de l'organisation accepté")
	}
}

// TestInvitationAnswersAlikeAndMustBeAccepted (SEC-09) : l'invitation répond de même que
// le compte existe ou non ; le compte n'est membre qu'après acceptation ; une invitation
// ne vaut que pour l'adresse invitée, une fois, avant son échéance.
func TestInvitationAnswersAlikeAndMustBeAccepted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	admin, bob, eve := f.user(t, "admin@example.org"), f.user(t, "bob@example.org"), f.user(t, "eve@example.org")
	o, _ := f.orgs.Create(ctx, audit.System, "atelier", "Atelier", "fr", admin.ID)

	if err := f.orgs.Invite(ctx, audit.System, o.ID, "Bob@Example.org", tenant.RoleMember); err != nil {
		t.Fatalf("compte existant : %v", err)
	}
	if err := f.orgs.Invite(ctx, audit.System, o.ID, "absent@example.org", tenant.RoleMember); err != nil {
		t.Fatalf("compte absent : %v", err)
	}
	if err := f.orgs.Invite(ctx, audit.System, o.ID, admin.Email, tenant.RoleMember); err != nil {
		t.Fatalf("membre existant : %v", err)
	}
	if err := f.orgs.Invite(ctx, audit.System, o.ID, "x", tenant.RoleMember); err == nil {
		t.Fatal("adresse invalide acceptée")
	}
	if err := f.orgs.Invite(ctx, audit.System, o.ID, "z@example.org", "viewer"); !isKey(err, org.KeyRoleInvalid) {
		t.Fatalf("rôle inconnu : %v", err)
	}
	list, err := f.orgs.Invitations(ctx, o.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("invitations : %+v, %v", list, err)
	}
	// Une nouvelle invitation remplace la précédente.
	if err := f.orgs.Invite(ctx, audit.System, o.ID, bob.Email, tenant.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if list, _ = f.orgs.Invitations(ctx, o.ID); len(list) != 2 {
		t.Fatalf("invitation renouvelée en double : %+v", list)
	}
	if _, err := f.orgs.Access(ctx, "atelier", bob.ID); !errors.Is(err, org.ErrNoAccess) {
		t.Fatalf("membre avant acceptation : %v", err)
	}
	pending, err := f.orgs.PendingInvitations(ctx, bob.ID)
	if err != nil || len(pending) != 1 || pending[0].Org != o.ID || pending[0].Role != tenant.RoleAdmin || pending[0].Slug != "atelier" {
		t.Fatalf("invitations de Bob : %+v, %v", pending, err)
	}
	if mine, _ := f.orgs.PendingInvitations(ctx, eve.ID); len(mine) != 0 {
		t.Fatalf("Ève voit l'invitation de Bob : %+v", mine)
	}
	// L'invitation de Bob ne vaut pas pour Ève.
	if _, err := f.orgs.AcceptInvitation(ctx, audit.System, eve.ID, pending[0].ID); !isKey(err, org.KeyInvitationUnknown) {
		t.Fatalf("acceptation par un autre compte : %v", err)
	}
	got, err := f.orgs.AcceptInvitation(ctx, audit.Actor{UserID: bob.ID, Email: bob.Email}, bob.ID, pending[0].ID)
	if err != nil || got != o.ID {
		t.Fatalf("acceptation : %v, %v", got, err)
	}
	acc, err := f.orgs.Access(ctx, "atelier", bob.ID)
	if err != nil || acc.Role != tenant.RoleAdmin {
		t.Fatalf("accès après acceptation : %+v, %v", acc, err)
	}
	if _, err := f.orgs.AcceptInvitation(ctx, audit.System, bob.ID, pending[0].ID); !isKey(err, org.KeyInvitationUnknown) {
		t.Fatalf("seconde acceptation : %v", err)
	}
	// Échéance : une invitation expirée n'est plus proposée ni acceptable.
	if err := f.orgs.Invite(ctx, audit.System, o.ID, eve.Email, tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	evePending, _ := f.orgs.PendingInvitations(ctx, eve.ID)
	if len(evePending) != 1 {
		t.Fatalf("invitation d'Ève : %+v", evePending)
	}
	if err := f.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `UPDATE org_invitations SET expires_at = now() - interval '1 second' WHERE email = $1`, eve.Email)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if mine, _ := f.orgs.PendingInvitations(ctx, eve.ID); len(mine) != 0 {
		t.Fatalf("invitation expirée proposée : %+v", mine)
	}
	if _, err := f.orgs.AcceptInvitation(ctx, audit.System, eve.ID, evePending[0].ID); !isKey(err, org.KeyInvitationUnknown) {
		t.Fatalf("invitation expirée acceptée : %v", err)
	}
	// Déclin et révocation.
	if err := f.orgs.Invite(ctx, audit.System, o.ID, eve.Email, tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	evePending, _ = f.orgs.PendingInvitations(ctx, eve.ID)
	if err := f.orgs.DeclineInvitation(ctx, audit.System, eve.ID, evePending[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.orgs.Access(ctx, "atelier", eve.ID); !errors.Is(err, org.ErrNoAccess) {
		t.Fatalf("membre après refus : %v", err)
	}
	list, _ = f.orgs.Invitations(ctx, o.ID)
	for _, i := range list {
		if i.Email == "absent@example.org" {
			if err := f.orgs.RevokeInvitation(ctx, audit.System, o.ID, i.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.orgs.RevokeInvitation(ctx, audit.System, o.ID, i.ID); !errors.Is(err, org.ErrNotFound) {
				t.Fatalf("seconde révocation : %v", err)
			}
		}
	}
	got2 := f.actions(t, o.ID)
	for _, want := range []audit.Action{audit.MemberInvited, audit.InvitationAccepted, audit.InvitationDeclined, audit.InvitationRevoked} {
		if !slices.Contains(got2, want) {
			t.Errorf("journal sans %s", want)
		}
	}
}

// TestInvitationsOfAnArchivedOrganizationVanish : une organisation archivée ne propose
// plus ses invitations, et elles ne s'acceptent plus.
func TestInvitationsOfAnArchivedOrganizationVanish(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	admin, bob := f.user(t, "admin@example.org"), f.user(t, "bob@example.org")
	o, _ := f.orgs.Create(ctx, audit.System, "o", "O", "fr", admin.ID)
	if err := f.orgs.Invite(ctx, audit.System, o.ID, bob.Email, tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	pending, _ := f.orgs.PendingInvitations(ctx, bob.ID)
	if err := f.orgs.SetArchived(ctx, audit.System, o.ID, true); err != nil {
		t.Fatal(err)
	}
	if now, _ := f.orgs.PendingInvitations(ctx, bob.ID); len(now) != 0 {
		t.Fatalf("invitation d'une organisation archivée : %+v", now)
	}
	if _, err := f.orgs.AcceptInvitation(ctx, audit.System, bob.ID, pending[0].ID); !isKey(err, org.KeyInvitationUnknown) {
		t.Fatalf("acceptation : %v", err)
	}
}
