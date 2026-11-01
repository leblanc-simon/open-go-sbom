//go:build integration

package finding

import (
	"context"
	"testing"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/vulntest"
)

// sides renvoie les instantanés de la branche main, du plus ancien au plus récent.
func (e *env) sides() []EffectSide {
	e.t.Helper()
	var out []EffectSide
	err := e.pool.InOrg(context.Background(), e.org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(context.Background(), `SELECT id, ref_id, set_id FROM snapshots WHERE ref_id = $1 ORDER BY scanned_at, id`, e.main)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s EffectSide
			if err := rows.Scan(&s.SnapshotID, &s.RefID, &s.SetID); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func vulnIDs(rows []Row) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.VulnID+" "+r.ComponentVersion)
	}
	return out
}

// TestUpgradeFixingCVEIsResolvedFinding : critère d'acceptation de T17 — une montée de
// version qui corrige une CVE apparaît comme « constat résolu » ; une vulnérabilité
// présente avant et après la montée n'est ni résolue ni introduite ; le chemin inverse
// l'introduit ; un composant inchangé n'apparaît pas.
func TestUpgradeFixingCVEIsResolvedFinding(t *testing.T) {
	e := newEnv(t)
	both := func(purl string) vulntest.Rule {
		return vulntest.Rule{PURL: purl, Vuln: vuln.Vulnerability{ID: "CVE-2099-0002", Severity: vuln.SeverityMedium, Risk: 5}}
	}
	e.publish(built1, log4shellRule(), apiRule(), both(log4jOld), both(log4jNew))
	e.push(testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	e.push(sbomWith(t, "2.17.1"))
	s := e.sides()
	if len(s) != 2 {
		t.Fatalf("%d instantanés", len(s))
	}
	svc := NewService(e.pool)
	ctx := context.Background()

	// Avant l'analyse du nouvel instantané : l'effet est signalé incomplet.
	eff, err := svc.Effect(ctx, e.org, s[0], s[1])
	if err != nil || !eff.Pending {
		t.Fatalf("avant analyse : %+v, %v", eff, err)
	}

	e.analyze(e.org, e.main)
	eff, err = svc.Effect(ctx, e.org, s[0], s[1])
	if err != nil {
		t.Fatal(err)
	}
	if eff.Pending || eff.ResolvedTotal != 1 || eff.IntroducedTotal != 0 || len(eff.Resolved) != 1 {
		t.Fatalf("effet de la montée : %+v", eff)
	}
	if r := eff.Resolved[0]; r.VulnID != "CVE-2021-44228" || r.ComponentVersion != "2.14.1" || r.Status != StatusResolved {
		t.Fatalf("constat résolu : %+v", r)
	}

	// Chemin inverse : la CVE est introduite (constat de la référence sur l'ancienne
	// version, résolu depuis, mais introduit par ce passage).
	eff, err = svc.Effect(ctx, e.org, s[1], s[0])
	if err != nil || eff.ResolvedTotal != 0 || eff.IntroducedTotal != 1 || vulnIDs(eff.Introduced)[0] != "CVE-2021-44228 2.14.1" {
		t.Fatalf("effet inverse : %v / %v, %v", vulnIDs(eff.Introduced), vulnIDs(eff.Resolved), err)
	}
	// Même instantané : aucun effet.
	if eff, err = svc.Effect(ctx, e.org, s[1], s[1]); err != nil || eff.ResolvedTotal+eff.IntroducedTotal != 0 {
		t.Fatalf("même instantané : %+v, %v", eff, err)
	}

	// Un constat résolu parce que la base ne juge plus le composant vulnérable
	// (not_matched) n'est pas une vulnérabilité résolue par l'instantané.
	e.execIn(e.org, `UPDATE findings SET resolution = 'not_matched' WHERE vuln_id = 'CVE-2021-44228'`)
	if eff, err = svc.Effect(ctx, e.org, s[0], s[1]); err != nil || eff.ResolvedTotal != 0 {
		t.Fatalf("fiche retirée : %v, %v", vulnIDs(eff.Resolved), err)
	}

	// Isolement : une autre organisation ne voit aucun constat de ces instantanés.
	other, _, _, _ := e.newOrg("autre")
	if eff, err := svc.Effect(ctx, other, s[0], s[1]); err != nil || eff.ResolvedTotal+eff.IntroducedTotal != 0 || eff.Pending {
		t.Fatalf("autre organisation : %+v, %v", eff, err)
	}
}
