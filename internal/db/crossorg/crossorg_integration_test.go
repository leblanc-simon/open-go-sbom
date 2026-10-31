//go:build integration

package crossorg_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/tenant"
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

// TestTokenOrgResolvesOnlyActiveOrganizations : l'organisation d'un jeton n'est résolue
// que si elle est active, et la fonction ne renvoie rien d'autre que son identifiant.
func TestTokenOrgResolvesOnlyActiveOrganizations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	q := tdb.App.DB()
	mk := func(slug, agentPub, enrPub string, archived bool) tenant.OrgID {
		id, _ := tenant.NewOrgID()
		if err := tdb.App.InOrg(ctx, id, func(tx *db.OrgTx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language, archived_at)
				VALUES ($1, $2, $2, 'fr', CASE WHEN $3 THEN now() END)`, id, slug, archived); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, gen_random_uuid(), 'repo', 'ci')`, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO agent_tokens (org_id, id, agent_id, public_id, secret_hash, name)
				SELECT $1, gen_random_uuid(), a.id, $2, sha256('s'::bytea), 'initial' FROM agents a`, id, agentPub); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens (org_id, id, public_id, secret_hash, name, expires_at, max_uses)
				VALUES ($1, gen_random_uuid(), $2, sha256('s'::bytea), 'parc', now() + interval '1 hour', 1)`, id, enrPub)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := mk("a", strings.Repeat("a", 26), strings.Repeat("b", 26), false)
	mk("z", strings.Repeat("c", 26), strings.Repeat("d", 26), true)

	if got, err := crossorg.AgentTokenOrg(ctx, q, strings.Repeat("a", 26)); err != nil || got != a {
		t.Fatalf("jeton d'agent : %v %v", got, err)
	}
	if got, err := crossorg.EnrollmentTokenOrg(ctx, q, strings.Repeat("b", 26)); err != nil || got != a {
		t.Fatalf("jeton d'inscription : %v %v", got, err)
	}
	for name, c := range map[string]struct {
		fn  func(context.Context, db.Querier, string) (tenant.OrgID, error)
		pub string
	}{
		"agent, organisation archivée":       {crossorg.AgentTokenOrg, strings.Repeat("c", 26)},
		"inscription, organisation archivée": {crossorg.EnrollmentTokenOrg, strings.Repeat("d", 26)},
		"agent inconnu":                      {crossorg.AgentTokenOrg, strings.Repeat("e", 26)},
		"identifiant d'inscription en agent": {crossorg.AgentTokenOrg, strings.Repeat("b", 26)},
	} {
		if _, err := c.fn(ctx, q, c.pub); !errors.Is(err, crossorg.ErrUnknownToken) {
			t.Errorf("%s : %v", name, err)
		}
	}
}
