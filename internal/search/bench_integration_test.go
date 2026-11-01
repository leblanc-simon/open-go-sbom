//go:build integration

package search

import (
	"context"
	"io"
	"net/url"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"leblanc.io/lotor/internal/benchdata"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// TestSearchBenchmark mesure la recherche sur le jeu de référence (1 000 projets,
// 1 million de liens) selon docs/benchmarks.md : rôle d'exécution, RLS active, froid puis
// 50 passages chauds, 95e centile sous 2 s. Long : seulement avec LOTOR_BENCH=1
// (make bench-search).
func TestSearchBenchmark(t *testing.T) {
	if os.Getenv("LOTOR_BENCH") != "1" {
		t.Skip("LOTOR_BENCH=1 pour mesurer la recherche sur le jeu de référence")
	}
	ctx := context.Background()
	start := time.Now()
	d, org := planDataset(t, benchdata.Reference())
	t.Logf("jeu de référence et compléments générés et analysés en %s", time.Since(start).Round(time.Second))
	svc := NewService(d.App, cmp)
	req := func(params string) Request {
		v, err := url.ParseQuery(params)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRequest(v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	second := req("q=lib-1&sort=name")
	first, err := svc.Search(ctx, org, tenant.AllTeams(), second)
	if err != nil {
		t.Fatal(err)
	}
	second.Cursor = first.NextCursor
	cases := []struct {
		name string
		run  func(i int) (Result, error)
	}{
		{"nom large (lib-1, 1 000 composants)", func(int) (Result, error) { return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1")) }},
		{"nom précis (lib-<i>)", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-"+strconv.Itoa(1234+i)))
		}},
		{"plage vers sur lodash (une occurrence par projet)", func(int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=pkg:npm/lodash+vers:npm/<4.17.20"))
		}},
		{"purl d'un paquet", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=pkg:maven/org.bench/lib-"+strconv.Itoa(5*i+1)))
		}},
		{"vulnérabilité", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=CVE-2099-"+[]string{"00001", "00002", "00941", "00050", "00100"}[i%5]))
		}},
		{"empreinte", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q="+url.QueryEscape(benchdata.SearchHash(i))))
		}},
		{"nom large filtré (sévérité moyenne, dépôts, tri par instantané)", func(int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1&severity=medium&type=repo&sort=snapshot"))
		}},
		{"page suivante (curseur)", func(int) (Result, error) { return svc.Search(ctx, org, tenant.AllTeams(), second) }},
	}
	for _, c := range cases {
		var ds []time.Duration
		var cold time.Duration
		var res Result
		for i := range 51 {
			s := time.Now()
			r, err := c.run(i)
			if err != nil {
				t.Fatalf("%s : %v", c.name, err)
			}
			if i == 0 {
				cold, res = time.Since(s), r
				continue
			}
			ds = append(ds, time.Since(s))
		}
		slices.Sort(ds)
		p95 := ds[len(ds)*95/100]
		t.Logf("%s : %d occurrences, %d projets ; froid %s, p50 %s, p95 %s, max %s", c.name, res.Hits, res.Projects,
			cold.Round(time.Millisecond), ds[len(ds)/2].Round(time.Millisecond), p95.Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))
		if p95 > 2*time.Second {
			t.Errorf("%s : p95 %s au-delà de 2 s", c.name, p95)
		}
	}
	// Export de toutes les occurrences d'une recherche large.
	var ds []time.Duration
	for range 20 {
		s := time.Now()
		if err := svc.Export(ctx, org, tenant.AllTeams(), req("q=lib-1"), FormatCSV, io.Discard); err != nil {
			t.Fatal(err)
		}
		ds = append(ds, time.Since(s))
	}
	slices.Sort(ds)
	t.Logf("export CSV (lib-1) : p50 %s, p95 %s, max %s", ds[len(ds)/2].Round(time.Millisecond),
		ds[len(ds)*95/100].Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))

	// Plans réels (EXPLAIN ANALYZE, RLS active) consignés dans docs/benchmarks.md.
	resolve := func(q string) target {
		var tg target
		query, err := Parse(q, cmp)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
			var err error
			tg, err = svc.resolve(ctx, tx, query)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return tg
	}
	for _, q := range []string{"pkg:npm/lodash vers:npm/<4.17.20", "lib-1", "CVE-2099-00001"} {
		a := &args{}
		hits := hitsSQL(resolve(q), Filters{}, nil, a)
		t.Logf("plan des occurrences de %q :\n%s", q, explain(t, d.App, org, true, `SELECT count(*) FROM (`+hits+`) h`, a.list...))
	}
}
