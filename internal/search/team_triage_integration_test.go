//go:build integration

package search

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
)

// decide trie le constat vulnID du projet slug au statut st (portée projet).
func (f *fixture) decide(slug, vulnID string, st triage.Status) {
	f.t.Helper()
	ctx := context.Background()
	var findingID uuid.UUID
	if err := f.pool.InOrg(ctx, f.a, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT id FROM findings WHERE project_id = $1 AND vuln_id = $2 AND status = 'open' LIMIT 1`,
			f.projects[slug], vulnID).Scan(&findingID)
	}); err != nil {
		f.t.Fatal(err)
	}
	in := triage.Input{ProjectID: f.projects[slug], FindingID: findingID, Scope: triage.ScopeProject, Status: st,
		Comment: "essai de la recherche"}
	if st == triage.StatusNotAffected {
		in.Justification = triage.Justification("vulnerable_code_not_in_execute_path")
	}
	svc := triage.NewService(triage.Options{Pool: f.pool, Comparer: cmp})
	if _, _, err := svc.Decide(ctx, f.a, audit.Actor{UserID: 0, Email: "analyste@example.org"}, in); err != nil {
		f.t.Fatal(err)
	}
}

// TestSearchTeamFilter : le filtre « équipe » restreint les résultats aux projets des
// équipes choisies ; une équipe invisible du compte ne donne rien ; le résultat nomme
// l'équipe de chaque projet (écran, API, export).
func TestSearchTeamFilter(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ops := uuid.Must(uuid.NewV7())
	general := f.a.UUID()
	f.exec(f.a, `INSERT INTO teams (org_id, id, name) VALUES ($1, $2, 'Exploitation')`, f.a, ops)
	f.exec(f.a, `UPDATE projects SET team_id = $1 WHERE id = $2`, ops, f.projects["srv-db-02"])

	all := f.run(f.a, "q=log4j-core")
	if all.Projects != 3 {
		t.Fatalf("sans filtre : %d projets", all.Projects)
	}
	for _, g := range all.Groups {
		want := "Général"
		if g.Project.Slug == "srv-db-02" {
			want = "Exploitation"
		}
		if g.Project.Team.Name != want {
			t.Errorf("%s : équipe %+v, attendu %s", g.Project.Slug, g.Project.Team, want)
		}
	}
	res := f.run(f.a, "q=log4j-core&team="+ops.String())
	expectOccurrences(t, res, "srv-db-02/srv-db-02:"+log4jOld)
	res = f.run(f.a, "q=log4j-core&team="+ops.String()+"&team="+general.String())
	if res.Projects != 3 {
		t.Fatalf("deux équipes : %d projets", res.Projects)
	}
	// Un compte qui ne voit que « Général » n'obtient rien en filtrant sur une autre
	// équipe, et ne voit jamais ses projets.
	onlyGeneral := tenant.OnlyTeams(general)
	req := f.request("q=log4j-core&team=" + ops.String())
	if r, err := f.search.Search(context.Background(), f.a, onlyGeneral, req); err != nil || r.Projects != 0 {
		t.Fatalf("équipe invisible : %d projets, %v", r.Projects, err)
	}
	// Une équipe d'une autre organisation ne donne rien non plus.
	if r := f.run(f.a, "q=log4j-core&team="+f.b.String()); r.Projects != 0 {
		t.Fatalf("équipe d'une autre organisation : %d projets", r.Projects)
	}

	var buf bytes.Buffer
	if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), f.request("q=log4j-core&team="+ops.String()), FormatCSV, &buf); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("export : %d lignes, %v", len(rows), err)
	}
	team := slices.Index(rows[0], "team")
	if team < 0 || rows[1][team] != "Exploitation" {
		t.Fatalf("colonne team : %v / %v", rows[0], rows[1])
	}
}

// TestSearchTriageStatus : une recherche par vulnérabilité montre le statut de triage de
// chaque constat et se filtre par statut ; le filtre est refusé pour une autre recherche ;
// une recherche par composant ne compte plus les constats « non affecté » ou « faux
// positif ».
func TestSearchTriageStatus(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.decide("srv-db-02", "CVE-2021-44228", triage.StatusNotAffected)

	res := f.run(f.a, "q=CVE-2021-44228")
	statuses := map[string]triage.Status{}
	for _, g := range res.Groups {
		for _, h := range g.Hits {
			statuses[g.Project.Slug] = h.Triage
			if h.FindingID == uuid.Nil {
				t.Errorf("%s : constat sans identifiant", g.Project.Slug)
			}
		}
	}
	if statuses["rapports"] != triage.StatusInTriage || statuses["srv-db-02"] != triage.StatusNotAffected {
		t.Fatalf("statuts de triage : %v", statuses)
	}
	expectOccurrences(t, f.run(f.a, "q=CVE-2021-44228&triage=not_affected"), "srv-db-02/srv-db-02:"+log4jOld)
	expectOccurrences(t, f.run(f.a, "q=CVE-2021-44228&triage=in_triage&triage=affected"), "rapports/main:"+log4jVuln)

	// Filtre de triage sur une recherche par composant : refusé, pas ignoré.
	_, err := f.search.Search(context.Background(), f.a, tenant.AllTeams(), f.request("q=log4j-core&triage=affected"))
	if e, ok := IsError(err); !ok || e.Key != KeyTriageVulnOnly {
		t.Fatalf("triage sur un composant : %v", err)
	}
	if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), f.request("q=log4j-core&triage=affected"), FormatJSON, &bytes.Buffer{}); err == nil {
		t.Fatal("export : triage sur un composant accepté")
	} else if e, ok := IsError(err); !ok || e.Key != KeyTriageVulnOnly {
		t.Fatalf("export : %v", errors.Unwrap(err))
	}

	// Recherche par composant : le constat « non affecté » de srv-db-02 n'est plus compté.
	comp := f.run(f.a, "q=pkg:maven/org.apache.logging.log4j/log4j-core@2.11.2")
	if len(comp.Groups) != 1 || comp.Groups[0].Hits[0].Open != 0 || comp.Groups[0].Hits[0].Severity != "" ||
		len(comp.Groups[0].Hits[0].Fixed) != 0 {
		t.Fatalf("composant trié non affecté : %+v", comp.Groups)
	}
	if r := f.run(f.a, "q=pkg:maven/org.apache.logging.log4j/log4j-core@2.11.2&severity=none"); r.Projects != 1 {
		t.Fatalf("sévérité « aucune » : %d projets", r.Projects)
	}

	// Export JSON : statut de triage et équipe.
	var buf bytes.Buffer
	if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), f.request("q=CVE-2021-44228&triage=not_affected"), FormatJSON, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Results) != 1 || doc.Results[0]["triage_status"] != "not_affected" || doc.Results[0]["team"] != "Général" {
		t.Fatalf("export JSON : %v", doc.Results)
	}
	if !strings.Contains(buf.String(), `"team_id"`) {
		t.Error("team_id absent de l'export JSON")
	}
}
