//go:build integration

package dashboard

import (
	"context"
	"testing"

	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/vuln"
)

// container crée un conteneur de l'hôte host (projet enfant) et sa référence.
func (f *fixture) container(slug, host, key string, archived bool) {
	var arch any
	if archived {
		arch = now.Add(-day24)
	}
	f.exec(`INSERT INTO projects (org_id, id, kind, slug, name, team_id, parent_id, parent_kind, container_key, container, seen_at,
		archived_at, archived_absent) VALUES ($1, $2, 'container', $3, $3, $1, $4, 'host', $5, '{}', $6, $7::timestamptz, $7::timestamptz IS NOT NULL)`,
		f.org, f.name(slug), slug, f.id(host), key, now, arch)
	ref, snap := f.name(slug+"/"+key), f.name("snap:"+slug+"/"+key)
	f.exec(`INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'container', 'container', $4)`,
		f.org, ref, f.id(slug), key)
	f.exec(`INSERT INTO snapshots (org_id, id, project_id, ref_id, scanned_at, last_scanned_at, blob_id, set_id, format,
		spec_version, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, 'syft', '16.0', $5, $5)`,
		f.org, snap, f.id(slug), ref, now, f.blob, f.set)
}

// TestFamilyCountsProjectVulnerabilityPairs : la fiche d'un hôte compte les couples
// distincts (projet, vulnérabilité) de l'hôte et de ses conteneurs actifs ; une même CVE
// sur l'hôte et sur deux conteneurs compte trois fois, une même CVE sur deux composants
// d'un même conteneur une fois.
func TestFamilyCountsProjectVulnerabilityPairs(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	f := newFixture(t, tdb.App, "fam")
	f.project("srv", "host", false)
	f.container("srv-web", "srv", "shop/web", false)
	f.container("srv-api", "srv", "shop/api", false)
	f.container("srv-old", "srv", "old", true)
	f.project("autre", "repo", false)
	for _, c := range [][3]string{{"openssl", "pkg:apk/alpine/openssl", "3.1.0"}, {"libssl", "pkg:apk/alpine/libssl3", "3.1.0"},
		{"zlib", "pkg:apk/alpine/zlib", "1.2.13"}} {
		f.component(c[0], c[1], c[2])
	}
	vulnerability(t, tdb.App, "CVE-2026-0001", "high", true)
	vulnerability(t, tdb.App, "CVE-2026-0002", "medium", false)
	// La même CVE sur l'hôte et sur les deux conteneurs actifs : trois couples.
	f.finding("srv/host", "openssl", "CVE-2026-0001", "high", true, 80, now, nil)
	f.finding("srv-web/shop/web", "openssl", "CVE-2026-0001", "high", true, 70, now, nil)
	f.finding("srv-api/shop/api", "openssl", "CVE-2026-0001", "high", true, 60, now, nil)
	// Sur deux composants d'un même conteneur : un couple, à sa plus haute sévérité.
	f.finding("srv-web/shop/web", "libssl", "CVE-2026-0001", "critical", true, 90, now, nil)
	f.finding("srv-web/shop/web", "zlib", "CVE-2026-0002", "medium", false, 20, now, nil)
	// Un constat résolu, un conteneur archivé, un autre projet : hors du compte.
	f.finding("srv-api/shop/api", "zlib", "CVE-2026-0002", "medium", false, 20, now.Add(-2*day24), ago(day24))
	f.finding("srv-old/old", "zlib", "CVE-2026-0002", "medium", false, 99, now, nil)
	f.finding("autre/main", "zlib", "CVE-2026-0002", "medium", false, 99, now, nil)
	// Un constat trié « non affecté » (T14) : hors du compte, comme au tableau de bord.
	vulnerability(t, tdb.App, "CVE-2026-0003", "critical", true)
	f.finding("srv-api/shop/api", "zlib", "CVE-2026-0003", "critical", true, 95, now, nil)
	decision := newID()
	f.exec(`INSERT INTO triage_decisions (org_id, id, scope, vuln_id, purl_base, action, status, justification, author_label, created_at)
		VALUES ($1, $2, 'org', 'CVE-2026-0003', 'pkg:apk/alpine/zlib', 'set', 'not_affected', 'code_not_reachable', 'system', now())`,
		f.org, decision)
	f.exec(`UPDATE findings SET triage_status = 'not_affected', triage_decision_id = $1 WHERE vuln_id = 'CVE-2026-0003'`, decision)

	fam, err := NewService(tdb.App).Family(context.Background(), f.org, f.id("srv"))
	if err != nil {
		t.Fatal(err)
	}
	if fam.Host.Open.Total() != 1 || fam.Host.Open.Of(vuln.SeverityHigh) != 1 || fam.Host.Open.KEV != 1 || fam.Host.MaxRisk != 80 {
		t.Errorf("hôte : %+v", fam.Host)
	}
	web := fam.Children[f.id("srv-web")]
	if web.Open.Total() != 2 || web.Open.Of(vuln.SeverityCritical) != 1 || web.Open.Of(vuln.SeverityMedium) != 1 || web.Open.KEV != 1 ||
		web.MaxRisk != 90 {
		t.Errorf("conteneur web : %+v", web)
	}
	if api := fam.Children[f.id("srv-api")]; api.Open.Total() != 1 || api.Open.Of(vuln.SeverityHigh) != 1 {
		t.Errorf("conteneur api : %+v", api)
	}
	if old := fam.Children[f.id("srv-old")]; old.Open.Total() != 1 {
		t.Errorf("conteneur archivé : %+v", old)
	}
	// CVE-2026-0001 compte trois fois (hôte, web, api), CVE-2026-0002 une fois (web).
	if fam.Total.Open.Total() != 4 || fam.Total.Open.KEV != 3 || fam.Total.Open.Of(vuln.SeverityHigh) != 2 ||
		fam.Total.Open.Of(vuln.SeverityCritical) != 1 || fam.Total.Open.Of(vuln.SeverityMedium) != 1 || fam.Total.MaxRisk != 90 {
		t.Errorf("total : %+v", fam.Total)
	}
}
