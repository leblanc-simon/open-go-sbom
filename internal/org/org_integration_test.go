//go:build integration

package org_test

import (
	"context"
	"errors"
	"testing"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/tenant"
)

func isKey(err error, k string) bool {
	v, ok := account.IsValidation(err)
	return ok && v.Key == k
}

type fixture struct {
	tdb      *dbtest.DB
	accounts *account.Service
	orgs     *org.Service
}

func setup(t *testing.T) fixture {
	t.Helper()
	tdb := dbtest.New(t)
	return fixture{tdb: tdb, accounts: account.NewService(tdb.App, 4), orgs: org.NewService(tdb.App)}
}

func (f fixture) user(t *testing.T, email string) account.User {
	t.Helper()
	u, _, err := f.accounts.Create(context.Background(), audit.System, email, false)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCreateValidatesAndRegistersFirstAdmin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	u := f.user(t, "u@example.org")
	for _, c := range []struct {
		slug, name, lang, key string
		admin                 int64
	}{
		{"Pas-Bon", "Nom", "fr", org.KeySlugInvalid, u.ID},
		{"-tiret", "Nom", "fr", org.KeySlugInvalid, u.ID},
		{"ok", "  ", "fr", org.KeyNameInvalid, u.ID},
		{"ok", "Nom", "de", org.KeyLanguage, u.ID},
		{"ok", "Nom", "fr", org.KeyUnknownAccount, 9999},
	} {
		if _, err := f.orgs.Create(ctx, audit.System, c.slug, c.name, c.lang, c.admin); !isKey(err, c.key) {
			t.Errorf("%s : %v", c.key, err)
		}
	}
	o, err := f.orgs.Create(ctx, audit.System, "atelier", " Atelier ", "fr", u.ID)
	if err != nil || o.Name != "Atelier" {
		t.Fatalf("création : %+v, %v", o, err)
	}
	if _, err := f.orgs.Create(ctx, audit.System, "atelier", "Bis", "fr", u.ID); !isKey(err, org.KeySlugTaken) {
		t.Fatalf("slug pris : %v", err)
	}
	acc, err := crossorg.Access(ctx, f.tdb.App.DB(), "atelier", u.ID)
	if err != nil || acc.Org != o.ID || acc.Role != tenant.RoleAdmin || acc.Language != "fr" {
		t.Fatalf("accès : %+v, %v", acc, err)
	}
	if id, err := crossorg.OrgIDBySlug(ctx, f.tdb.App.DB(), "atelier"); err != nil || id != o.ID {
		t.Fatalf("slug : %v, %v", id, err)
	}
	if _, err := crossorg.OrgIDBySlug(ctx, f.tdb.App.DB(), "absente"); !errors.Is(err, crossorg.ErrNotFound) {
		t.Fatalf("slug absent : %v", err)
	}
	if _, err := crossorg.ListOrganizations(ctx, f.tdb.App.DB(), "", 0); err == nil {
		t.Fatal("taille 0 acceptée")
	}
	list, err := crossorg.ListOrganizations(ctx, f.tdb.App.DB(), "", 10)
	if err != nil || len(list) != 1 || list[0].Members != 1 {
		t.Fatalf("liste : %+v, %v", list, err)
	}
	var events int
	if err := f.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		p, err := audit.ListOrg(ctx, tx, "", audit.MaxPage)
		events = len(p.Items)
		return err
	}); err != nil || events != 3 { // org.created, member.added, team.created
		t.Fatalf("journal de l'organisation : %d, %v", events, err)
	}
}

// TestOrganizationKeepsOneAdmin : le dernier administrateur ne peut être ni rétrogradé
// ni retiré.
func TestOrganizationKeepsOneAdmin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	a, b := f.user(t, "a@example.org"), f.user(t, "b@example.org")
	o, _ := f.orgs.Create(ctx, audit.System, "o", "O", "fr", a.ID)
	if err := f.orgs.SetMemberRole(ctx, audit.System, o.ID, a.ID, tenant.RoleMember); !isKey(err, org.KeyLastOrgAdmin) {
		t.Fatalf("rétrogradation : %v", err)
	}
	if err := f.orgs.RemoveMember(ctx, audit.System, o.ID, a.ID); !isKey(err, org.KeyLastOrgAdmin) {
		t.Fatalf("retrait : %v", err)
	}
	if err := f.orgs.AddMember(ctx, audit.System, o.ID, b.Email, "chef"); !isKey(err, org.KeyRoleInvalid) {
		t.Fatalf("rôle inconnu : %v", err)
	}
	if err := f.orgs.AddMember(ctx, audit.System, o.ID, "x", tenant.RoleMember); !isKey(err, account.KeyEmailInvalid) {
		t.Fatalf("adresse invalide : %v", err)
	}
	if err := f.orgs.AddMember(ctx, audit.System, o.ID, b.Email, tenant.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.AddMember(ctx, audit.System, o.ID, b.Email, tenant.RoleAdmin); !isKey(err, org.KeyMemberExists) {
		t.Fatalf("doublon : %v", err)
	}
	if err := f.orgs.SetMemberRole(ctx, audit.System, o.ID, a.ID, tenant.RoleAdmin); err != nil {
		t.Fatalf("rôle inchangé : %v", err)
	}
	if err := f.orgs.SetMemberRole(ctx, audit.System, o.ID, a.ID, "chef"); !isKey(err, org.KeyRoleInvalid) {
		t.Fatalf("rôle inconnu : %v", err)
	}
	if err := f.orgs.SetMemberRole(ctx, audit.System, o.ID, a.ID, tenant.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := f.orgs.RemoveMember(ctx, audit.System, o.ID, 9999); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("membre inconnu : %v", err)
	}
	if m, err := f.orgs.Member(ctx, o.ID, a.ID); err != nil || m.Email != a.Email || m.Role != tenant.RoleMember || !m.Active {
		t.Fatalf("membre : %+v, %v", m, err)
	}
	if _, err := f.orgs.Member(ctx, o.ID, 9999); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("membre inconnu : %v", err)
	}
	other, _ := f.orgs.Create(ctx, audit.System, "autre", "Autre", "fr", b.ID)
	if _, err := f.orgs.Member(ctx, other.ID, a.ID); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("membre d'une autre organisation : %v", err)
	}
	admins, err := f.orgs.Admins(ctx, o.ID)
	if err != nil || len(admins) != 1 || admins[0].UserID != b.ID {
		t.Fatalf("administrateurs : %+v, %v", admins, err)
	}
	p1, err := f.orgs.Members(ctx, o.ID, "", 1)
	if err != nil || len(p1.Items) != 1 || p1.NextCursor == "" {
		t.Fatalf("page 1 : %+v, %v", p1, err)
	}
	p2, err := f.orgs.Members(ctx, o.ID, p1.NextCursor, 1)
	if err != nil || len(p2.Items) != 1 || p2.Items[0].Email != "b@example.org" {
		t.Fatalf("page 2 : %+v, %v", p2, err)
	}
	if _, err := f.orgs.Members(ctx, o.ID, "x", 1); err == nil {
		t.Fatal("curseur illisible accepté")
	}
	if _, err := f.orgs.Members(ctx, o.ID, "", 0); err == nil {
		t.Fatal("taille 0 acceptée")
	}
}

func TestUpdateAndArchive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	a := f.user(t, "a@example.org")
	o, _ := f.orgs.Create(ctx, audit.System, "o", "O", "fr", a.ID)
	if err := f.orgs.Update(ctx, audit.System, o.ID, "", "fr"); !isKey(err, org.KeyNameInvalid) {
		t.Fatalf("nom vide : %v", err)
	}
	if err := f.orgs.Update(ctx, audit.System, o.ID, "O", "xx"); !isKey(err, org.KeyLanguage) {
		t.Fatalf("langue : %v", err)
	}
	if err := f.orgs.Update(ctx, audit.System, o.ID, "Nouveau", "en"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.orgs.Get(ctx, o.ID); got.Name != "Nouveau" || got.DefaultLanguage != "en" {
		t.Fatalf("modifiée : %+v", got)
	}
	for _, archived := range []bool{true, true, false} {
		if err := f.orgs.SetArchived(ctx, audit.System, o.ID, archived); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.orgs.SetArchived(ctx, audit.System, o.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := crossorg.Access(ctx, f.tdb.App.DB(), "o", a.ID); !errors.Is(err, crossorg.ErrNoAccess) {
		t.Fatalf("organisation archivée accessible : %v", err)
	}
	if orgs, err := crossorg.UserOrgs(ctx, f.tdb.App.DB(), a.ID); err != nil || len(orgs) != 0 {
		t.Fatalf("organisation archivée au sélecteur : %+v, %v", orgs, err)
	}
	unknown, _ := tenant.NewOrgID()
	if _, err := f.orgs.Get(ctx, unknown); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("organisation inconnue : %v", err)
	}
	if err := f.orgs.Update(ctx, audit.System, unknown, "X", "fr"); !errors.Is(err, org.ErrNotFound) {
		t.Fatalf("modification d'une organisation inconnue : %v", err)
	}
}
