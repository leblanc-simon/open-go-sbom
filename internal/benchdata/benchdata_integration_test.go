//go:build integration

package benchdata

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/tenant"
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

// TestAddTeamsAndContainersSmall : le complément du lot 2 répartit les dépôts entre les
// équipes, ajoute hôtes et conteneurs dans l'équipe de leur hôte, avec inventaire et
// constats, et des décisions de triage qui donnent leur statut aux constats.
func TestAddTeamsAndContainersSmall(t *testing.T) {
	ctx := context.Background()
	d := dbtest.New(t)
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	p := Params{Projects: 20, Links: 2000, Components: 1009, Vulnerabilities: 50, VulnerableEvery: 10}
	base, err := Generate(ctx, d.App, org, "bench", p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := AddTeamsAndContainers(ctx, d.App, org, p, TeamParams{Teams: 4, Hosts: 3, ContainersPerHost: 2, ContainerComponents: 50, TriageEvery: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Teams) != 4 || st.Teams[0] != org.UUID() || st.Hosts != 3 || st.Containers != 6 || st.Links != base.Links+9*50 ||
		st.Findings <= base.Findings || st.Decisions == 0 {
		t.Fatalf("complément %s (jeu %s)", st, base)
	}
	var badTeam, perTeam, decided, undecided int
	if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM projects c JOIN projects h ON h.id = c.parent_id WHERE c.team_id <> h.team_id),
			(SELECT count(DISTINCT team_id) FROM projects WHERE kind = 'repo'),
			(SELECT count(*) FROM findings WHERE triage_decision_id IS NOT NULL AND triage_status <> 'in_triage'),
			(SELECT count(*) FROM triage_decisions d WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.triage_decision_id = d.id))`).
			Scan(&badTeam, &perTeam, &decided, &undecided)
	}); err != nil {
		t.Fatal(err)
	}
	if badTeam != 0 || perTeam != 4 || decided != st.Decisions || undecided != 0 {
		t.Fatalf("équipes des conteneurs %d, équipes des dépôts %d, constats décidés %d pour %d décisions (%d sans constat)",
			badTeam, perTeam, decided, st.Decisions, undecided)
	}
	if _, err := AddTeamsAndContainers(ctx, d.App, org, p, TeamParams{}); err == nil {
		t.Fatal("paramètres nuls acceptés")
	}
}

// TestReferenceDataset génère le jeu de référence (1 000 projets, 1 million de liens) et
// mesure les lectures de T06 selon docs/benchmarks.md. Long : seulement avec
// LOTOR_BENCH=1.
func TestReferenceDataset(t *testing.T) {
	if os.Getenv("LOTOR_BENCH") != "1" {
		t.Skip("LOTOR_BENCH=1 pour générer le jeu de référence")
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
	// Complément du lot 2 (T18) : équipes, hôtes et conteneurs, décisions de triage.
	ts, err := AddTeamsAndContainers(ctx, d.App, org, Reference(), ReferenceTeams())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("complément : %s", ts)
	member := tenant.OnlyTeams(ts.Teams[1])
	if _, err := d.Owner(t).ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatal(err)
	}
	s := finding.NewService(d.App)
	var projects []uuid.UUID
	err = d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM projects WHERE kind = 'repo' ORDER BY slug LIMIT 50`)
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
		_, _, _, err := s.Vulnerability(ctx, org, tenant.AllTeams(), "CVE-2099-00"+[]string{"001", "021", "041", "061", "081"}[i%5], finding.StatusOpen)
		return err
	})
	measure("fiche composant", func(i int) error {
		_, err := s.Component(ctx, org, tenant.AllTeams(), "pkg:npm/lib-"+[]string{"0", "100", "200", "300", "400"}[i%5])
		return err
	})
	measure("fiche vulnérabilité (membre d'une équipe)", func(i int) error {
		_, _, _, err := s.Vulnerability(ctx, org, member, "CVE-2099-00"+[]string{"001", "021", "041", "061", "081"}[i%5], finding.StatusOpen)
		return err
	})
	measure("fiche composant (membre d'une équipe)", func(i int) error {
		_, err := s.Component(ctx, org, member, "pkg:npm/lib-"+[]string{"0", "100", "200", "300", "400"}[i%5])
		return err
	})
}
