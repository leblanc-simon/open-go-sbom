//go:build integration

package web

import (
	"context"
	"net/http"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"leblanc.io/lotor/internal/benchdata"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// TestReferenceDatasetDashboard mesure le tableau de bord et la fiche projet, pages HTML
// complètes (garde, lectures sous la RLS, rendu), sur le jeu de référence de T06 complété
// d'un an de statistiques quotidiennes (organisation et 1 000 projets) et de 1 000 agents,
// selon docs/benchmarks.md (cible : 1 s au 95e centile). Long : seulement avec
// LOTOR_BENCH=1 (make bench).
func TestReferenceDatasetDashboard(t *testing.T) {
	if os.Getenv("LOTOR_BENCH") != "1" {
		t.Skip("LOTOR_BENCH=1 pour générer le jeu de référence")
	}
	ctx := context.Background()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	st, err := benchdata.Generate(ctx, a.tdb.App, org, "bench", benchdata.Reference())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("jeu : %s", st)
	// Complément du lot 2 (T18) : équipes, hôtes et conteneurs, décisions de triage.
	ts, err := benchdata.AddTeamsAndContainers(ctx, a.tdb.App, org, benchdata.Reference(), benchdata.ReferenceTeams())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("complément : %s", ts)
	member := a.user("member@example.org", false)
	if err := a.tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		for _, q := range []string{
			`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, ` + strconv.FormatInt(admin.ID, 10) + `, 'admin')`,
			// Membre d'une seule équipe (1 sur 10) : tableau de bord additionné par projet.
			`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, ` + strconv.FormatInt(member.ID, 10) + `, 'member')`,
			`INSERT INTO team_members (org_id, team_id, user_id, role) VALUES ($1, '` + ts.Teams[1].String() + `', ` +
				strconv.FormatInt(member.ID, 10) + `, 'reader')`,
			`INSERT INTO agents (org_id, id, kind, name, last_seen_at)
			 SELECT $1, gen_random_uuid(), 'repo', 'agent-' || g, now() - (g % 30) * interval '1 day' FROM generate_series(1, 1000) g`,
			`INSERT INTO org_daily_stats (org_id, day, open_critical, open_high, open_medium, open_low, open_negligible, open_unknown,
			        open_kev, kev_vulns, projects, silent_agents, fixed_critical, fixed_high, fixed_medium, fixed_low, fixed_negligible,
			        fixed_unknown, fix_p50_critical, fix_p50_high, recorded_at)
			 SELECT $1, current_date - g, 1300 + g, 10000 + g, 34000 - g, 20000, 0, 2000, 700, 50, 1000, 10, 1, 2, 3, 4, 0, 0,
			        86400 * 3, 86400 * 9, now()
			   FROM generate_series(1, 365) g`,
			`INSERT INTO project_daily_stats (org_id, project_id, day, open_critical, open_high, open_medium, open_low,
			        open_negligible, open_unknown, open_kev, recorded_at)
			 SELECT p.org_id, p.id, current_date - g, 1, 10, 34, 20, 0, 2, 1, now()
			   FROM projects p CROSS JOIN generate_series(1, 365) g WHERE p.org_id = $1`,
		} {
			if _, err := tx.ExecContext(ctx, q, org); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.tdb.Owner(t).ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := a.dash.Record(ctx, org); err != nil {
		t.Fatal(err)
	}
	t.Logf("enregistrement des statistiques du jour : %s", time.Since(start))

	b := a.signIn(admin)
	measure := func(name string, path func(i int) string) {
		measureAs(t, b, name, path)
	}
	measure("tableau de bord (90 jours)", func(int) string { return "/o/bench" })
	measure("tableau de bord (12 mois)", func(int) string { return "/o/bench?period=365" })
	measure("fiche projet (90 jours)", func(i int) string { return "/o/bench/projects/p-" + strconv.Itoa(i%50+1) })
	// Lot 2 (T18) : fiche d'un hôte et de ses 10 conteneurs (périmètre), d'un conteneur,
	// et tableau de bord d'un membre d'une seule équipe.
	measure("fiche hôte avec ses conteneurs (90 jours)", func(i int) string { return "/o/bench/projects/h-" + strconv.Itoa(i%50+1) })
	measure("fiche conteneur (90 jours)", func(i int) string {
		return "/o/bench/projects/h-" + strconv.Itoa(i%50+1) + "-c" + strconv.Itoa(i%10+1)
	})
	m := a.signIn(member)
	// h-1, h-11… sont dans l'équipe du membre (n mod 10 = 1), comme p-1, p-11…
	measureAs(t, m, "tableau de bord, membre d'une équipe (90 jours)", func(int) string { return "/o/bench" })
	measureAs(t, m, "tableau de bord, membre d'une équipe (12 mois)", func(int) string { return "/o/bench?period=365" })
	measureAs(t, m, "fiche projet, membre d'une équipe", func(i int) string { return "/o/bench/projects/p-" + strconv.Itoa(10*(i%50)+1) })
}

// measureAs mesure 50 chargements d'une page par le navigateur b (le premier compté comme
// froid) ; cible : 1 s au 95e centile.
func measureAs(t *testing.T, b *browser, name string, path func(i int) string) {
	t.Helper()
	var ds []time.Duration
	for i := range 50 {
		begin := time.Now()
		if p := b.get(path(i)); p.status != http.StatusOK {
			t.Fatalf("%s : %d", path(i), p.status)
		}
		ds = append(ds, time.Since(begin))
	}
	cold := ds[0]
	slices.Sort(ds)
	p95 := ds[len(ds)*95/100]
	t.Logf("%s : froid %s, p50 %s, p95 %s, max %s", name, cold, ds[len(ds)/2], p95, ds[len(ds)-1])
	if p95 > time.Second {
		t.Errorf("%s : p95 %s au-delà de la cible d'1 s", name, p95)
	}
}
