//go:build integration

package finding

import (
	"context"
	"errors"
	"testing"

	"leblanc.io/lotor/internal/vuln"
)

// TestReads : lectures des écrans (constats d'un projet, décomptes, fiche vulnérabilité,
// famille d'un composant), RLS comprise.
func TestReads(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(built1, log4shellRule(), apiRule())
	e.push(testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	s := NewService(e.pool)
	page, err := s.Project(ctx, e.org, e.repo, Filter{}, "", 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].VulnID != "CVE-2021-44228" || page.NextCursor == "" {
		t.Fatalf("première page : %+v, %v", page, err)
	}
	r := page.Items[0]
	if !r.KEV || r.CVSS == nil || *r.CVSS != 10 || r.EPSS == nil || r.ComponentVersion != "2.14.1" || r.RefName != "main" ||
		r.ProjectSlug != "depot" || r.FixState != vuln.FixFixed || r.Status != StatusOpen {
		t.Fatalf("constat %+v", r)
	}
	next, err := s.Project(ctx, e.org, e.repo, Filter{}, page.NextCursor, 1)
	if err != nil || len(next.Items) != 1 || next.Items[0].VulnID != "CVE-2099-0001" || next.NextCursor != "" {
		t.Fatalf("seconde page : %+v, %v", next, err)
	}
	for _, c := range []struct {
		f    Filter
		want int
	}{{Filter{Severity: vuln.SeverityLow}, 1}, {Filter{KEVOnly: true}, 1}, {Filter{RefID: e.main}, 2}, {Filter{Status: StatusResolved}, 0}} {
		p, err := s.Project(ctx, e.org, e.repo, c.f, "", 10)
		if err != nil || len(p.Items) != c.want {
			t.Errorf("filtre %+v : %d constats, %v", c.f, len(p.Items), err)
		}
	}
	if _, err := s.Project(ctx, e.org, e.repo, Filter{}, "illisible", 10); err == nil {
		t.Error("curseur illisible accepté")
	}
	if _, err := s.Project(ctx, e.org, e.repo, Filter{}, "", PageMax+1); err == nil {
		t.Error("page démesurée acceptée")
	}
	counts, err := s.RefCounts(ctx, e.org, e.repo)
	c := counts[e.main]
	if err != nil || c.Open != 2 || c.KEV != 1 || c.Of(vuln.SeverityCritical) != 1 || c.Of(vuln.SeverityLow) != 1 || Sum(counts).Open != 2 {
		t.Fatalf("décomptes %+v, %v", counts, err)
	}
	an, err := s.Analyses(ctx, e.org, e.repo)
	if err != nil || an[e.main].Matches != 2 || !an[e.main].Built.Equal(built1) {
		t.Fatalf("analyses %+v, %v", an, err)
	}
	entry, rows, vc, err := s.Vulnerability(ctx, e.org, "GHSA-jfh8-c2jp-5v3q", StatusOpen)
	if err != nil || entry.ID != "CVE-2021-44228" || len(rows) != 1 || vc.Open != 1 || vc.Projects != 1 || vc.Resolved != 0 {
		t.Fatalf("fiche vulnérabilité : %+v %d %+v, %v", entry, len(rows), vc, err)
	}
	if _, _, _, err := s.Vulnerability(ctx, e.org, "CVE-0000-0000", StatusOpen); !errors.Is(err, vuln.ErrNotFound) {
		t.Fatalf("vulnérabilité inconnue : %v", err)
	}
	comp, err := s.Component(ctx, e.org, "pkg:maven/org.apache.logging.log4j/log4j-core")
	if err != nil || len(comp) != 1 {
		t.Fatalf("famille du composant : %d, %v", len(comp), err)
	}
	// Une autre organisation ne voit rien de ces constats.
	org2, _, _, _ := e.newOrg("autre")
	if _, rows, _, err := s.Vulnerability(ctx, org2, "CVE-2021-44228", StatusOpen); err != nil || len(rows) != 0 {
		t.Fatalf("constats de A vus de B : %d, %v", len(rows), err)
	}
	if p, err := s.Project(ctx, org2, e.repo, Filter{}, "", 10); err != nil || len(p.Items) != 0 {
		t.Fatalf("projet de A lu depuis B : %d, %v", len(p.Items), err)
	}
	if c, err := s.Component(ctx, org2, "pkg:maven/org.apache.logging.log4j/log4j-core"); err != nil || len(c) != 0 {
		t.Fatalf("composants de A lus depuis B : %d, %v", len(c), err)
	}
}
