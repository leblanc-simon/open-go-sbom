//go:build integration

package crossorg_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/crossorg"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// TestSearchFunctionsStayInTheDeclaredOrganization : les fonctions de recherche
// contournent la RLS pour leurs index, mais n'en sortent pas : elles ne renvoient que des
// composants de l'organisation déclarée par InOrg, et échouent hors InOrg.
func TestSearchFunctionsStayInTheDeclaredOrganization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	names := map[tenant.OrgID]map[string]uuid.UUID{}
	mk := func(slug string, comps ...[2]string) tenant.OrgID {
		org, _ := tenant.NewOrgID()
		names[org] = map[string]uuid.UUID{}
		if err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, $2, 'fr')`, org, slug); err != nil {
				return err
			}
			for i, c := range comps {
				id := uuid.Must(uuid.NewV7())
				names[org][c[0]] = id
				hashes := []string{}
				if c[1] != "" {
					hashes = append(hashes, c[1])
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO components (org_id, id, purl, purl_base, type, name, version, hashes)
					VALUES ($1, $2, $3, $4, 'npm', $5, $6, $7)`, org, id, fmt.Sprintf("pkg:npm/%s@1.0.%d", c[0], i),
					"pkg:npm/"+c[0], c[0], fmt.Sprintf("1.0.%d", i), hashes); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return org
	}
	h := "sha256:" + fmt.Sprintf("%064x", 7)
	a := mk("a", [2]string{"lodash", h}, [2]string{"lodash.merge", ""}, [2]string{"Lodash-ES", ""}, [2]string{"qs", ""},
		[2]string{"my_lib", ""}, [2]string{"myxlib", ""})
	b := mk("b", [2]string{"lodash", h}, [2]string{"qs", ""})

	find := func(org tenant.OrgID, fn func(context.Context, *db.OrgTx, string) (crossorg.ComponentMatches, error), q string) crossorg.ComponentMatches {
		t.Helper()
		var m crossorg.ComponentMatches
		if err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
			var err error
			m, err = fn(ctx, tx, q)
			return err
		}, db.ReadOnly()); err != nil {
			t.Fatal(err)
		}
		return m
	}
	ids := func(org tenant.OrgID, ns ...string) []uuid.UUID {
		var out []uuid.UUID
		for _, n := range ns {
			out = append(out, names[org][n])
		}
		return out
	}

	// Nom exact d'abord, puis par ressemblance ; jamais un composant de B.
	m := find(a, crossorg.ComponentsByName, "lodash")
	if m.Approx || m.Truncated || len(m.IDs) != 3 || m.IDs[0] != names[a]["lodash"] {
		t.Fatalf("lodash dans A : %+v", m)
	}
	for _, id := range m.IDs {
		if slices.Contains(ids(b, "lodash", "qs"), id) {
			t.Fatal("composant de B renvoyé dans A")
		}
	}
	if m := find(b, crossorg.ComponentsByName, "LODASH"); !slices.Equal(m.IDs, ids(b, "lodash")) {
		t.Fatalf("lodash dans B : %+v", m)
	}
	// Moins de trois caractères : nom exact seulement.
	if m := find(a, crossorg.ComponentsByName, "QS"); !slices.Equal(m.IDs, ids(a, "qs")) {
		t.Fatalf("qs : %+v", m)
	}
	// « _ » et « % » sont des caractères, pas des jokers.
	if m := find(a, crossorg.ComponentsByName, "my_lib"); !slices.Equal(m.IDs, ids(a, "my_lib")) {
		t.Fatalf("my_lib : %+v", m)
	}
	if m := find(a, crossorg.ComponentsByName, "%dash"); len(m.IDs) != 0 && !m.Approx {
		t.Fatalf("joker accepté : %+v", m)
	}
	// Faute de frappe : aucun nom ne contient « lodahs », la ressemblance le retrouve.
	if m := find(a, crossorg.ComponentsByName, "lodahs"); !m.Approx || len(m.IDs) == 0 || m.IDs[0] != names[a]["lodash"] {
		t.Fatalf("lodahs : %+v", m)
	}
	// Empreinte : seulement celle de l'organisation déclarée.
	if m := find(a, crossorg.ComponentsByHash, h); !slices.Equal(m.IDs, ids(a, "lodash")) {
		t.Fatalf("empreinte dans A : %+v", m)
	}
	if m := find(b, crossorg.ComponentsByHash, h); !slices.Equal(m.IDs, ids(b, "lodash")) {
		t.Fatalf("empreinte dans B : %+v", m)
	}

	// Hors InOrg (connexion neuve, puis connexion réutilisée après un InOrg) : échec franc.
	for _, q := range []string{`SELECT count(*) FROM ogsbom_search_component_names('lodash', 10)`,
		`SELECT count(*) FROM ogsbom_search_component_hashes('` + h + `', 10)`} {
		var n int
		if err := tdb.App.DB().QueryRowContext(ctx, q).Scan(&n); err == nil {
			t.Fatalf("%s hors InOrg : %d lignes", q, n)
		}
	}
}

// TestSearchFunctionsTruncate : au-delà de MaxSearchComponents, le résultat est tronqué
// et le dit.
func TestSearchFunctionsTruncate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	org, _ := tenant.NewOrgID()
	var m crossorg.ComponentMatches
	err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, 'a', 'a', 'fr')`, org); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO components (org_id, id, purl, purl_base, type, name, version)
			SELECT $1, gen_random_uuid(), 'pkg:npm/lib-' || g || '@1.0.0', 'pkg:npm/lib-' || g, 'npm', 'lib-' || g, '1.0.0'
			  FROM generate_series(1, $2) g`, org, crossorg.MaxSearchComponents+5); err != nil {
			return err
		}
		var err error
		m, err = crossorg.ComponentsByName(ctx, tx, "lib-")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Truncated || len(m.IDs) != crossorg.MaxSearchComponents {
		t.Fatalf("troncature : %d, %v", len(m.IDs), m.Truncated)
	}
}
