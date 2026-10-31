//go:build integration

package crossorg_test

import (
	"context"
	"errors"
	"testing"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/crossorg"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// TestCrossOrgReturnsOnlyWhatIsNeeded : les fonctions inter-organisations ne renvoient que
// les organisations du compte (actives), ou les métadonnées pour l'administration.
func TestCrossOrgReturnsOnlyWhatIsNeeded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	q := tdb.App.DB()
	var alice, bob int64
	if err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		if err := tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash) VALUES ('a@x.org', 'x') RETURNING id`).Scan(&alice); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash) VALUES ('b@x.org', 'x') RETURNING id`).Scan(&bob)
	}); err != nil {
		t.Fatal(err)
	}
	mk := func(slug, lang string, member int64, role string, archived bool) tenant.OrgID {
		id, _ := tenant.NewOrgID()
		if err := tdb.App.InOrg(ctx, id, func(tx *db.OrgTx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language, archived_at)
				VALUES ($1, $2, upper($2), $3, CASE WHEN $4 THEN now() END)`, id, slug, lang, archived); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, $3)`, id, member, role)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := mk("a", "en", alice, "analyst", false)
	mk("b", "fr", bob, "admin", false)
	mk("c", "fr", alice, "viewer", true)

	acc, err := crossorg.Access(ctx, q, "a", alice)
	if err != nil || acc.Org != a || acc.Role != tenant.RoleAnalyst || acc.Language != "en" || acc.Name != "A" {
		t.Fatalf("accès : %+v, %v", acc, err)
	}
	for _, c := range []struct {
		slug string
		user int64
	}{{"b", alice}, {"c", alice}, {"z", alice}} {
		if _, err := crossorg.Access(ctx, q, c.slug, c.user); !errors.Is(err, crossorg.ErrNoAccess) {
			t.Errorf("%s : %v", c.slug, err)
		}
	}
	orgs, err := crossorg.UserOrgs(ctx, q, alice)
	if err != nil || len(orgs) != 1 || orgs[0].Slug != "a" {
		t.Fatalf("organisations d'alice : %+v, %v", orgs, err)
	}
	all, err := crossorg.ListOrganizations(ctx, q, "a", 10)
	if err != nil || len(all) != 2 || all[0].Slug != "b" || all[1].ArchivedAt == nil || all[0].Members != 1 {
		t.Fatalf("liste : %+v, %v", all, err)
	}
	if _, err := crossorg.ListOrganizations(ctx, q, "", crossorg.MaxPage+1); err == nil {
		t.Fatal("page trop grande acceptée")
	}
	if id, err := crossorg.OrgIDBySlug(ctx, q, "a"); err != nil || id != a {
		t.Fatalf("slug : %v, %v", id, err)
	}
	if _, err := crossorg.OrgIDBySlug(ctx, q, "z"); !errors.Is(err, crossorg.ErrNotFound) {
		t.Fatalf("slug inconnu : %v", err)
	}
}
