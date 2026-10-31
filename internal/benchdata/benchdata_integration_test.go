//go:build integration

package benchdata

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/finding"
	"leblanc.io/open-go-sbom/internal/tenant"
)

func TestGenerateSmall(t *testing.T) {
	d := dbtest.New(t)
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	p := Params{Projects: 20, Links: 2000, Components: 1009, Vulnerabilities: 50, VulnerableEvery: 10}
	st, err := Generate(context.Background(), d.App, org, "bench", p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Projects != 20 || st.Links != 2000 || st.Components != 1009 || st.Findings == 0 || st.Open >= st.Findings {
		t.Fatalf("jeu %s", st)
	}
	// Les lectures des écrans fonctionnent sur le jeu, sous la RLS.
	s := finding.NewService(d.App)
	var project, ref uuid.UUID
	if err := d.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT project_id, ref_id FROM findings LIMIT 1`).Scan(&project, &ref)
	}); err != nil {
		t.Fatal(err)
	}
	page, err := s.Project(context.Background(), org, project, finding.Filter{}, "", 50)
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("constats : %d, %v", len(page.Items), err)
	}
	if _, err := Generate(context.Background(), d.App, org, "bench", Params{}); err == nil {
		t.Fatal("paramètres nuls acceptés")
	}
}

// TestReferenceDataset génère le jeu de référence (1 000 projets, 1 million de liens) et
// mesure les lectures de T06 selon docs/benchmarks.md. Long : seulement avec
// OGSBOM_BENCH=1.
func TestReferenceDataset(t *testing.T) {
	if os.Getenv("OGSBOM_BENCH") != "1" {
		t.Skip("OGSBOM_BENCH=1 pour générer le jeu de référence")
	}
	ctx := context.Background()
	d := dbtest.New(t)
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	st, err := Generate(ctx, d.App, org, "bench", Reference())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("jeu : %s", st)
	if _, err := d.Owner(t).ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatal(err)
	}
	s := finding.NewService(d.App)
	var projects []uuid.UUID
	err = d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM projects ORDER BY slug LIMIT 50`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			projects = append(projects, id)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	measure := func(name string, fn func(i int) error) {
		t.Helper()
		var ds []time.Duration
		for i := range 50 {
			start := time.Now()
			if err := fn(i); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(start))
		}
		slices.Sort(ds)
		t.Logf("%s : p50 %s, p95 %s, max %s", name, ds[len(ds)/2], ds[len(ds)*95/100], ds[len(ds)-1])
	}
	measure("onglet Constats (page de 50)", func(i int) error {
		_, err := s.Project(ctx, org, projects[i%len(projects)], finding.Filter{}, "", 50)
		return err
	})
	measure("décomptes par référence", func(i int) error {
		_, err := s.RefCounts(ctx, org, projects[i%len(projects)])
		return err
	})
	measure("fiche vulnérabilité", func(i int) error {
		_, _, _, err := s.Vulnerability(ctx, org, "CVE-2099-00"+[]string{"001", "021", "041", "061", "081"}[i%5], finding.StatusOpen)
		return err
	})
	measure("fiche composant", func(i int) error {
		_, err := s.Component(ctx, org, "pkg:npm/lib-"+[]string{"0", "100", "200", "300", "400"}[i%5])
		return err
	})
}
