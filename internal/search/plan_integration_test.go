//go:build integration

package search

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/benchdata"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/tenant"
)

// planDataset : un jeu synthétique moyen, analysé (ANALYZE par le propriétaire), avec les
// compléments de la recherche.
func planDataset(t *testing.T, p benchdata.Params) (*dbtest.DB, tenant.OrgID) {
	t.Helper()
	ctx := context.Background()
	d := dbtest.New(t)
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := benchdata.Generate(ctx, d.App, org, "bench", p); err != nil {
		t.Fatal(err)
	}
	if err := benchdata.AddSearchFixtures(ctx, d.App, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Owner(t).ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatal(err)
	}
	return d, org
}

// explain renvoie le plan d'une requête, exécutée dans InOrg par le rôle d'exécution (RLS
// active). Sans parcours séquentiel permis, un index inutilisable sous la RLS (opérateur
// non LEAKPROOF) se voit : le plan retombe malgré tout sur un parcours séquentiel.
func explain(t *testing.T, pool *db.Pool, org tenant.OrgID, analyze bool, query string, args ...any) string {
	t.Helper()
	var plan []string
	opts := "EXPLAIN "
	if analyze {
		opts = "EXPLAIN (ANALYZE, BUFFERS) "
	}
	err := pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		if !analyze {
			if _, err := tx.ExecContext(context.Background(), `SET LOCAL enable_seqscan = off`); err != nil {
				return err
			}
		}
		rows, err := tx.QueryContext(context.Background(), opts+query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan = append(plan, line)
		}
		return rows.Err()
	}, db.ReadOnly())
	if err != nil {
		t.Fatalf("%s : %v", query, err)
	}
	return strings.Join(plan, "\n")
}

func ownerExplain(t *testing.T, owner *sql.DB, query string, args ...any) string {
	t.Helper()
	tx, err := owner.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query("EXPLAIN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, line)
	}
	return strings.Join(plan, "\n")
}

// TestSearchPlansUseTheirIndexes : malgré la RLS, chaque requête de la recherche passe
// par l'index prévu (critère d'acceptation). Les fonctions de recherche par nom et par
// empreinte, exécutées par le propriétaire, passent par leurs index GIN ; la même
// condition sous la RLS ne le peut pas, ce qui justifie ces fonctions (ADR 0024).
func TestSearchPlansUseTheirIndexes(t *testing.T) {
	t.Parallel()
	d, org := planDataset(t, benchdata.Params{Projects: 100, Links: 50_000, Components: 40_009, Vulnerabilities: 500, VulnerableEvery: 20})
	pool := d.App
	var ids []uuid.UUID
	if err := pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(context.Background(), `SELECT id FROM components WHERE purl_base = 'pkg:npm/lodash'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	a := &args{}
	hits := hitsSQL(target{components: ids}, Filters{}, nil, a)
	va := &args{}
	vhits := hitsSQL(target{vulnIDs: []string{"CVE-2099-00001"}}, Filters{}, nil, va)
	cases := []struct {
		name  string
		query string
		args  []any
		want  []string
	}{
		{"paquet (purl_base)", `SELECT id, purl FROM components WHERE purl_base = $1`, []any{"pkg:npm/lodash"},
			[]string{"components_purl_base_idx"}},
		{"occurrences de composants", hits, a.list, []string{"component_set_items_component_idx"}},
		{"constats d'une vulnérabilité", vhits, va.list, []string{"findings_vuln_idx"}},
		{"catalogue par alias", `SELECT id FROM vulnerabilities WHERE id = $1 OR aliases @> ARRAY[$1]`, []any{"GHSA-xxxx"},
			[]string{"vulnerabilities_aliases_idx"}},
	}
	for _, c := range cases {
		plan := explain(t, pool, org, false, c.query, c.args...)
		if strings.Contains(plan, "Seq Scan") {
			t.Errorf("%s : parcours séquentiel malgré enable_seqscan = off\n%s", c.name, plan)
		}
		for _, idx := range c.want {
			if !strings.Contains(plan, idx) {
				t.Errorf("%s : %s absent du plan\n%s", c.name, idx, plan)
			}
		}
	}
	owner := d.Owner(t)
	for name, c := range map[string]struct {
		query, want string
		args        []any
	}{
		"nom":       {`SELECT id FROM components WHERE org_id = $1 AND name ILIKE '%lib-4321%'`, "components_name_trgm_idx", []any{org}},
		"nom court": {`SELECT id FROM components WHERE org_id = $1 AND lower(name) = 'qs'`, "components_name_lower_idx", []any{org}},
		"empreinte": {`SELECT id FROM components WHERE org_id = $1 AND hashes @> ARRAY[$2]`, "components_hashes_idx", []any{org, benchdata.SearchHash(3)}},
	} {
		if plan := ownerExplain(t, owner, c.query, c.args...); !strings.Contains(plan, c.want) {
			t.Errorf("fonction de recherche par %s : %s absent du plan\n%s", name, c.want, plan)
		}
	}
	// Sous la RLS, ILIKE n'est pas LEAKPROOF : l'index trigramme ne sert pas.
	if plan := explain(t, pool, org, false, `SELECT id FROM components WHERE name ILIKE '%lib-12%'`); strings.Contains(plan, "components_name_trgm_idx") {
		t.Logf("PostgreSQL utilise l'index trigramme sous la RLS : les fonctions de recherche pourraient être revues\n%s", plan)
	}
}
