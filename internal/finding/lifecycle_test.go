package finding

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/vuln"
)

func TestMergeKeepsSurestMatchAndUnitesFixes(t *testing.T) {
	comp := uuid.New()
	components := map[string]uuid.UUID{"pkg:deb/debian/openssl@3": comp}
	vulns := map[string]vuln.Vulnerability{"CVE-1": {ID: "CVE-1", KEV: &vuln.KEV{},
		CVSS: []vuln.CVSS{{Version: "3.1", BaseScore: 7.5}}, EPSS: &vuln.EPSS{Score: 0.1}}}
	ms := []vuln.Match{
		{PURL: "pkg:deb/debian/openssl@3", VulnerabilityID: "CVE-1", Severity: vuln.SeverityCritical, Type: vuln.MatchCPE,
			FixedVersions: []string{"3.2"}, FixState: vuln.FixUnknown, Risk: 50},
		{PURL: "pkg:deb/debian/openssl@3", VulnerabilityID: "CVE-1", Severity: vuln.SeverityLow, Type: vuln.MatchExactIndirect,
			FixedVersions: []string{"3.1"}, FixState: vuln.FixFixed, Risk: 10},
		{PURL: "pkg:npm/absent@1", VulnerabilityID: "CVE-1"},
	}
	got, unmatched := merge(ms, components, vulns)
	if unmatched != 1 || len(got) != 1 {
		t.Fatalf("%d couples, %d hors inventaire", len(got), unmatched)
	}
	o := got[0]
	if o.MatchType != vuln.MatchExactIndirect || o.Severity != vuln.SeverityLow || o.Risk != 50 ||
		!slices.Equal(o.FixedVersions, []string{"3.1", "3.2"}) || o.FixState != vuln.FixFixed || !o.KEV || o.CVSS != 7.5 ||
		o.EPSS == nil {
		t.Fatalf("couple fusionné : %+v", o)
	}
	// Même type : la plus grave l'emporte, quel que soit l'ordre.
	ms[0].Type = vuln.MatchExactIndirect
	a, _ := merge(ms, components, vulns)
	slices.Reverse(ms)
	b, _ := merge(ms, components, vulns)
	if a[0].Severity != vuln.SeverityCritical || b[0].Severity != vuln.SeverityCritical || a[0].Risk != b[0].Risk {
		t.Fatalf("départage dépendant de l'ordre : %+v / %+v", a[0], b[0])
	}
}

// TestPlanLifecycle nomme les règles du cycle de vie d'un constat.
func TestPlanLifecycle(t *testing.T) {
	kept, gone, upgraded := uuid.New(), uuid.New(), uuid.New()
	open1, open2, open3, closed := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	existing := []current{
		{ID: open1, key: key{kept, "CVE-A"}, Status: StatusOpen},      // revu : prolongé
		{ID: open2, key: key{gone, "CVE-B"}, Status: StatusOpen},      // composant retiré
		{ID: open3, key: key{upgraded, "CVE-C"}, Status: StatusOpen},  // base : plus vulnérable
		{ID: closed, key: key{kept, "CVE-D"}, Status: StatusResolved}, // réapparaît : rouvert
	}
	seen := []observed{{key: key{kept, "CVE-A"}}, {key: key{kept, "CVE-D"}}, {key: key{kept, "CVE-E"}}}
	inSet := map[uuid.UUID]bool{kept: true, upgraded: true}
	p := planFor(existing, seen, inSet)
	if len(p.Create) != 1 || p.Create[0].Vuln != "CVE-E" {
		t.Errorf("nouveau couple créé : %+v", p.Create)
	}
	updates := map[uuid.UUID]bool{}
	for _, u := range p.Update {
		updates[u.ID] = u.Reopen
	}
	if len(updates) != 2 || updates[open1] || !updates[closed] {
		t.Errorf("prolongé et rouvert : %+v", p.Update)
	}
	reasons := map[uuid.UUID]Resolution{}
	for _, r := range p.Resolve {
		reasons[r.ID] = r.Reason
	}
	if len(reasons) != 2 || reasons[open2] != ResolutionComponentRemoved || reasons[open3] != ResolutionNotMatched {
		t.Errorf("résolutions : %+v", p.Resolve)
	}
	// Un constat déjà résolu absent de l'analyse reste tel quel.
	if p := planFor(existing[3:], nil, nil); len(p.Resolve)+len(p.Update)+len(p.Create) != 0 {
		t.Errorf("constat résolu retouché : %+v", p)
	}
}

func TestTypeRankAndPreferred(t *testing.T) {
	if typeRank(vuln.MatchExactDirect) >= typeRank(vuln.MatchExactIndirect) || typeRank(vuln.MatchExactIndirect) >= typeRank(vuln.MatchCPE) {
		t.Fatal("ordre des types")
	}
	a := observed{MatchType: vuln.MatchCPE, Severity: vuln.SeverityHigh, Risk: 2}
	b := observed{MatchType: vuln.MatchCPE, Severity: vuln.SeverityHigh, Risk: 1}
	if !preferred(a, b) || preferred(b, a) {
		t.Fatal("départage par le risque")
	}
	if joinList([]string{"a", "b"}) != "a\x1fb" || joinList(nil) != "" {
		t.Fatal("joinList")
	}
}
