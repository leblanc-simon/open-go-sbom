//go:build integration

package search

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
)

func expectOccurrences(t *testing.T, res Result, want ...string) {
	t.Helper()
	got := occurrences(res)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("occurrences :\n  %v\nattendu :\n  %v", got, want)
	}
}

// TestSearchKnownDataset : critères d'acceptation sur un petit jeu connu.
func TestSearchKnownDataset(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	t.Run("plage vers sur lodash", func(t *testing.T) {
		// vers:npm/<4.17.21 sur pkg:npm/lodash ne renvoie que les versions inférieures,
		// comparées selon npm (4.9.0 < 4.17.21), jamais comme du texte.
		res := f.run(f.a, "q=pkg:npm/lodash+vers:npm/<4.17.21")
		expectOccurrences(t, res, "portail/release/2.3:"+lodash20, "rapports/main:"+lodash9)
		if res.OutOfRange != 1 {
			t.Fatalf("hors plage : %d, attendu 1 (lodash 4.17.21 de portail)", res.OutOfRange)
		}
		// La version « latest » de srv-db-02 n'est pas comparable : signalée, pas ignorée.
		if len(res.Unreadable) != 1 || res.Unreadable[0] != (VersionCount{Version: "latest", Occurrences: 1}) {
			t.Fatalf("versions illisibles : %+v", res.Unreadable)
		}
		if res.Projects != 2 || res.Hits != 2 {
			t.Fatalf("décomptes : %d projets, %d occurrences", res.Projects, res.Hits)
		}
	})

	t.Run("purl avec version", func(t *testing.T) {
		res := f.run(f.a, "q=pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
		expectOccurrences(t, res, "rapports/main:"+log4jVuln)
		if res.OutOfRange != 2 {
			t.Fatalf("hors version : %d", res.OutOfRange)
		}
	})

	t.Run("CVE", func(t *testing.T) {
		// CVE-2021-44228 renvoie les projets touchés, avec statut et version corrigée.
		res := f.run(f.a, "q=CVE-2021-44228")
		expectOccurrences(t, res, "rapports/main:"+log4jVuln, "srv-db-02/srv-db-02:"+log4jOld)
		h := res.Groups[0].Hits[0]
		if res.Groups[0].Project.Slug != "rapports" || h.Status != finding.StatusOpen || h.VulnID != "CVE-2021-44228" ||
			!slices.Equal(h.Fixed, []string{"2.12.2", "2.15.0"}) || h.Severity != vuln.SeverityCritical || !h.KEV {
			t.Fatalf("constat : %+v", h)
		}
		// Un GHSA est ramené à son CVE par les alias du catalogue.
		ghsa := f.run(f.a, "q=GHSA-jfh8-c2jp-5v3q")
		if !slices.Equal(occurrences(ghsa), occurrences(res)) {
			t.Fatalf("GHSA : %v", occurrences(ghsa))
		}
	})

	t.Run("empreinte", func(t *testing.T) {
		// Le SHA-256 d'un fichier connu d'un SBOM d'exemple renvoie le composant et ses projets.
		res := f.run(f.a, "q="+jqueryHash)
		expectOccurrences(t, res, "portail/main:pkg:npm/jquery@3.4.1")
		if h := res.Groups[0].Hits[0]; h.Origin != sbom.OriginIA || h.Confidence == nil {
			t.Fatalf("origine IA : %+v", h)
		}
	})

	t.Run("nom", func(t *testing.T) {
		res := f.run(f.a, "q=log4j-core")
		expectOccurrences(t, res, "rapports/main:"+log4jVuln, "srv-db-02/srv-db-02:"+log4jOld, "portail/release/2.3:"+log4jFixed)
		var order []string
		for _, g := range res.Groups {
			order = append(order, g.Project.Slug)
		}
		if !slices.Equal(order, []string{"rapports", "srv-db-02", "portail"}) {
			t.Fatalf("tri par risque : %v", order)
		}
		if res.Approx || res.Truncated {
			t.Fatalf("drapeaux : %+v", res)
		}
		if typo := f.run(f.a, "q=log4j-croe"); !typo.Approx || typo.Hits == 0 {
			t.Fatalf("faute de frappe : %+v", typo)
		}
	})

	t.Run("filtres", func(t *testing.T) {
		cases := map[string][]string{
			"q=log4j-core&type=host":                       {"srv-db-02/srv-db-02:" + log4jOld},
			"q=log4j-core&label=env%3Dprod":                {"srv-db-02/srv-db-02:" + log4jOld, "portail/release/2.3:" + log4jFixed},
			"q=log4j-core&label=env%3Ddev&type=repo":       {"rapports/main:" + log4jVuln},
			"q=log4j-core&kev=1":                           {"rapports/main:" + log4jVuln, "srv-db-02/srv-db-02:" + log4jOld},
			"q=log4j-core&severity=none":                   {"portail/release/2.3:" + log4jFixed},
			"q=lodash&severity=high":                       {"portail/release/2.3:" + lodash20, "rapports/main:" + lodash9},
			"q=jquery&origin=ia":                           {"portail/main:pkg:npm/jquery@3.4.1"},
			"q=jquery&origin=syft":                         nil,
			"q=CVE-2021-44228&label=exposé-internet":       nil,
			"q=CVE-2021-44228&type=host&severity=critical": {"srv-db-02/srv-db-02:" + log4jOld},
		}
		for params, want := range cases {
			res := f.run(f.a, params)
			got := occurrences(res)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("%s : %v, attendu %v", params, got, want)
			}
		}
	})

	t.Run("pagination", func(t *testing.T) {
		for _, sort := range Sorts() {
			full := f.run(f.a, "q=lodash&sort="+string(sort))
			var paged []string
			req := f.request("q=lodash&limit=1&sort=" + string(sort))
			for range 10 {
				res, err := f.search.Search(context.Background(), f.a, tenant.AllTeams(), req)
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Groups) > 1 || res.Projects != full.Projects {
					t.Fatalf("page : %d groupes, %d projets", len(res.Groups), res.Projects)
				}
				paged = append(paged, occurrences(res)...)
				if res.NextCursor == "" {
					break
				}
				req.Cursor = res.NextCursor
			}
			if !slices.Equal(paged, occurrences(full)) {
				t.Fatalf("tri %s : pages %v ≠ %v", sort, paged, occurrences(full))
			}
		}
		// Un curseur d'un autre ordre est refusé.
		res := f.run(f.a, "q=lodash&limit=1")
		req := f.request("q=lodash&limit=1&sort=name")
		req.Cursor = res.NextCursor
		if _, err := f.search.Search(context.Background(), f.a, tenant.AllTeams(), req); err == nil {
			t.Fatal("curseur d'un autre ordre accepté")
		}
	})

	t.Run("isolement", func(t *testing.T) {
		// B ne voit que ses projets, A ne voit jamais b.
		expectOccurrences(t, f.run(f.b, "q=log4j-core"), "b/main:"+log4jVuln)
		expectOccurrences(t, f.run(f.b, "q=CVE-2021-44228"), "b/main:"+log4jVuln)
		if res := f.run(f.b, "q="+jqueryHash); res.Hits != 0 {
			t.Fatalf("empreinte de A vue par B : %v", occurrences(res))
		}
		for _, q := range []string{"q=log4j-core", "q=CVE-2021-44228", "q=pkg:npm/lodash"} {
			for _, o := range occurrences(f.run(f.a, q)) {
				if strings.HasPrefix(o, "b/") || strings.HasPrefix(o, "ancien/") || strings.Contains(o, "/old:") {
					t.Fatalf("%s : %s ne devrait pas apparaître", q, o)
				}
			}
		}
	})

	t.Run("export", func(t *testing.T) {
		req := f.request("q=log4j-core")
		var csvOut bytes.Buffer
		if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), req, FormatCSV, &csvOut); err != nil {
			t.Fatal(err)
		}
		records, err := csv.NewReader(&csvOut).ReadAll()
		if err != nil || len(records) != 4 || !slices.Equal(records[0], exportColumns) {
			t.Fatalf("CSV : %v, %v", records, err)
		}
		// Par nom de projet : portail, rapports, srv-db-02.
		if records[1][0] != "portail" || records[2][0] != "rapports" || records[2][8] != "2.14.1" || records[2][16] != "true" {
			t.Fatalf("lignes CSV : %v", records[1:])
		}
		var jsonOut bytes.Buffer
		if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), f.request("q=CVE-2021-44228"), FormatJSON, &jsonOut); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Query   string    `json:"query"`
			Kind    Kind      `json:"kind"`
			Results []jsonRow `json:"results"`
		}
		if err := json.Unmarshal(jsonOut.Bytes(), &doc); err != nil {
			t.Fatalf("JSON : %v\n%s", err, jsonOut.String())
		}
		if doc.Kind != KindVulnerability || len(doc.Results) != 2 || doc.Results[0].Status != "open" ||
			!slices.Equal(doc.Results[0].FixedVersions, []string{"2.12.2", "2.15.0"}) {
			t.Fatalf("JSON : %+v", doc)
		}
		var empty bytes.Buffer
		if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), f.request("q=inexistant-zzz"), FormatJSON, &empty); err != nil ||
			!json.Valid(empty.Bytes()) {
			t.Fatalf("export vide : %s, %v", empty.String(), err)
		}
		if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), req, Format("xml"), &empty); err == nil {
			t.Fatal("format inconnu accepté")
		}
	})

	t.Run("étiquettes", func(t *testing.T) {
		labels, err := f.search.Labels(context.Background(), f.a, tenant.AllTeams())
		if err != nil || !slices.Equal(labels, []string{"env=dev", "env=prod", "exposé-internet"}) {
			t.Fatalf("%v, %v", labels, err)
		}
	})
}

// TestSearchResolvedFindings : une vulnérabilité corrigée sort des projets touchés, et
// reste visible avec son statut quand on demande aussi les constats résolus.
func TestSearchResolvedFindings(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.push(f.a, f.agentOf(f.a, "depots"), f.projects["rapports"], "main", cdx(log4jFixed, log4jAPI))
	expectOccurrences(t, f.run(f.a, "q=CVE-2021-44228"), "srv-db-02/srv-db-02:"+log4jOld)
	res := f.run(f.a, "q=CVE-2021-44228&resolved=1")
	expectOccurrences(t, res, "srv-db-02/srv-db-02:"+log4jOld, "rapports/main:"+log4jVuln)
	for _, g := range res.Groups {
		for _, h := range g.Hits {
			if (g.Project.Slug == "rapports") != (h.Status == finding.StatusResolved) {
				t.Fatalf("%s : statut %s", g.Project.Slug, h.Status)
			}
		}
	}
}
