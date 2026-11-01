//go:build integration

package triage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/triage/vex"
)

// TestOrgDecisionAppliesProjectOverrides : une décision d'organisation s'applique à tous
// les projets concernés, une décision de projet la surcharge pour ce projet seulement ;
// les retraits rendent la main ; chaque décision est journalisée.
func TestOrgDecisionAppliesProjectOverrides(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := e.newOrg("triage")
	f.project("api")
	f.project("web")
	fa := f.finding("api", log4jOld, cve)
	fw := f.finding("web", log4jOld, cve)
	other := f.finding("api", log4jOld, "CVE-2099-0001")

	org := f.decide(triage.Input{ProjectID: f.id("api"), FindingID: fa, Scope: triage.ScopeOrg, Status: triage.StatusNotAffected,
		Justification: triage.JustCodeNotReachable})
	if f.status(fa) != triage.StatusNotAffected || f.status(fw) != triage.StatusNotAffected {
		t.Fatalf("décision d'organisation : api %s, web %s", f.status(fa), f.status(fw))
	}
	if f.status(other) != triage.StatusInTriage {
		t.Fatalf("autre vulnérabilité : %s", f.status(other))
	}
	proj := f.decide(triage.Input{ProjectID: f.id("api"), FindingID: fa, Scope: triage.ScopeProject, Status: triage.StatusAffected})
	if f.status(fa) != triage.StatusAffected || f.status(fw) != triage.StatusNotAffected {
		t.Fatalf("décision de projet : api %s, web %s", f.status(fa), f.status(fw))
	}
	// Une nouvelle décision d'organisation ne surcharge pas celle du projet.
	f.decide(triage.Input{ProjectID: f.id("web"), FindingID: fw, Scope: triage.ScopeOrg, Status: triage.StatusFalsePositive})
	if f.status(fa) != triage.StatusAffected || f.status(fw) != triage.StatusFalsePositive {
		t.Fatalf("seconde décision d'organisation : api %s, web %s", f.status(fa), f.status(fw))
	}
	if _, _, err := e.svc.Withdraw(context.Background(), f.org, e.actor, proj.ID, f.id("api")); err != nil {
		t.Fatal(err)
	}
	if f.status(fa) != triage.StatusFalsePositive {
		t.Fatalf("après retrait du projet : %s", f.status(fa))
	}
	// La première décision d'organisation n'est plus courante (même clé, plus récente).
	if _, _, err := e.svc.Withdraw(context.Background(), f.org, e.actor, org.ID, uuid.Nil); !errors.Is(err, triage.ErrNotFound) {
		t.Fatalf("retrait d'une décision remplacée : %v", err)
	}
	// Un retrait de projet ne vaut pas pour une décision d'organisation, et inversement.
	cur, err := e.svc.OrgDecisions(context.Background(), f.org)
	if err != nil || len(cur) != 1 || cur[0].Findings != 2 {
		t.Fatalf("décisions d'organisation %+v, %v", cur, err)
	}
	if _, _, err := e.svc.Withdraw(context.Background(), f.org, e.actor, cur[0].ID, f.id("api")); !errors.Is(err, triage.ErrNotFound) {
		t.Fatalf("retrait d'une décision d'organisation par un projet : %v", err)
	}
	if _, _, err := e.svc.Withdraw(context.Background(), f.org, e.actor, cur[0].ID, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if f.status(fa) != triage.StatusInTriage || f.status(fw) != triage.StatusInTriage {
		t.Fatalf("après retrait de l'organisation : api %s, web %s", f.status(fa), f.status(fw))
	}
	if n := f.count(`SELECT count(*) FROM triage_decisions`); n != 5 {
		t.Fatalf("%d lignes au journal des décisions, attendu 5 (ajout seul)", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action IN ('triage.decided', 'triage.withdrawn')`); n != 5 {
		t.Fatalf("%d événements d'audit, attendu 5", n)
	}
	if n := f.count(`SELECT count(*) FROM findings WHERE triage_decision_id IS NOT NULL`); n != 0 {
		t.Fatalf("%d constats gardent une décision après les retraits", n)
	}
	e.mu.Lock()
	n := len(e.changes)
	e.mu.Unlock()
	// 2 (org) + 1 (projet) + 1 (seconde org, web) + 1 (retrait projet) + 2 (retrait org).
	if n != 7 {
		t.Fatalf("%d changements reçus par OnChange, attendu 7", n)
	}
}

// TestOrgDecisionVersRange : une décision d'organisation restreinte à une plage vers ne
// vaut que pour les versions qu'elle contient.
func TestOrgDecisionVersRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := e.newOrg("vers")
	f.project("api")
	f.project("web")
	old := f.finding("api", log4jOld, cve)
	recent := f.finding("web", log4jNew, cve)
	d := f.decide(triage.Input{ProjectID: f.id("api"), FindingID: old, Scope: triage.ScopeOrg, Status: triage.StatusAffected,
		Vers: "vers:maven/ < 2.15.0"})
	if d.Vers != "vers:maven/<2.15.0" {
		t.Fatalf("plage normalisée %q", d.Vers)
	}
	if f.status(old) != triage.StatusAffected || f.status(recent) != triage.StatusInTriage {
		t.Fatalf("2.14.1 %s, 2.17.1 %s", f.status(old), f.status(recent))
	}
	_, _, err := e.svc.Decide(context.Background(), f.org, e.actor, triage.Input{ProjectID: f.id("api"), FindingID: old,
		Scope: triage.ScopeOrg, Status: triage.StatusAffected, Comment: "x", Vers: "vers:npm/<1.0.0"})
	if v, ok := account.IsValidation(err); !ok || v.Key != triage.KeyVersInvalid {
		t.Fatalf("plage d'un autre écosystème : %v", err)
	}
}

// TestNewFindingInheritsDecision : un constat créé après une décision en hérite (Classify,
// appelé par l'analyse dans sa transaction).
func TestNewFindingInheritsDecision(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := e.newOrg("inherit")
	f.project("api")
	f.project("web")
	first := f.finding("api", log4jOld, cve)
	f.decide(triage.Input{ProjectID: f.id("api"), FindingID: first, Scope: triage.ScopeOrg, Status: triage.StatusNotAffected,
		Justification: triage.JustVulnerableCodeNotPresent})
	f.decide(triage.Input{ProjectID: f.id("api"), FindingID: first, Scope: triage.ScopeProject, Status: triage.StatusRiskAccepted,
		ExpiresOn: date(e.clock.Now().AddDate(0, 1, 0))})
	later := f.finding("web", log4jOld, cve)
	f.ref("api", "release")
	again := f.findingOn("api", "release", log4jOld, cve) // même composant, autre référence du projet
	if f.status(later) != triage.StatusInTriage {
		t.Fatal("constat classé avant Classify")
	}
	if err := e.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return e.svc.Classify(context.Background(), tx, []uuid.UUID{later, again})
	}); err != nil {
		t.Fatal(err)
	}
	if f.status(later) != triage.StatusNotAffected || f.status(again) != triage.StatusRiskAccepted {
		t.Fatalf("nouveaux constats : web %s, api %s", f.status(later), f.status(again))
	}
}

// TestRiskAcceptedExpiresSameDay : un risque accepté échu revient « à analyser » le jour
// même, par le job mis en file avec la décision, et laisse une trace.
func TestRiskAcceptedExpiresSameDay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := e.newOrg("expire")
	f.project("api")
	fid := f.finding("api", log4jOld, cve)
	f.decide(triage.Input{ProjectID: f.id("api"), FindingID: fid, Scope: triage.ScopeOrg, Status: triage.StatusAffected})
	today := e.clock.Now()
	d := f.decide(triage.Input{ProjectID: f.id("api"), FindingID: fid, Scope: triage.ScopeProject,
		Status: triage.StatusRiskAccepted, ExpiresOn: date(today)})
	due := d.ExpiresAt()
	var runAt time.Time
	if err := e.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT run_at FROM jobs WHERE kind = $1 AND unique_key = $2`,
			triage.ExpireKind, "decision:"+d.ID.String()).Scan(&runAt)
	}); err != nil {
		t.Fatal(err)
	}
	if !runAt.Equal(due) {
		t.Fatalf("échéance du job %v, attendu %v", runAt, due)
	}
	// Une minute avant minuit : rien ne change.
	e.clock.set(due.Add(-time.Minute))
	if done, err := e.svc.Expire(context.Background(), f.org, d.ID); err != nil || done {
		t.Fatalf("échéance anticipée : %v, %v", done, err)
	}
	if f.status(fid) != triage.StatusRiskAccepted {
		t.Fatalf("avant l'échéance : %s", f.status(fid))
	}
	// Le jour suivant à 00:01 : retour « à analyser », pas à la décision d'organisation.
	e.clock.set(due.Add(time.Minute))
	if done, err := e.svc.Expire(context.Background(), f.org, d.ID); err != nil || !done {
		t.Fatalf("échéance : %v, %v", done, err)
	}
	if f.status(fid) != triage.StatusInTriage {
		t.Fatalf("après l'échéance : %s", f.status(fid))
	}
	if n := f.count(`SELECT count(*) FROM triage_decisions WHERE action = 'expire' AND expires_id = $1 AND author_label = 'system'`, d.ID); n != 1 {
		t.Fatalf("%d lignes d'échéance", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action = 'triage.expired' AND actor_user_id IS NULL`); n != 1 {
		t.Fatalf("%d événements d'échéance", n)
	}
	// Idempotent : un second passage ne change rien.
	if done, err := e.svc.Expire(context.Background(), f.org, d.ID); err != nil || done {
		t.Fatalf("second passage : %v, %v", done, err)
	}
	h, err := e.svc.History(context.Background(), f.org, f.id("api"), fid)
	if err != nil || len(h) != 3 || h[0].Action != triage.ActionExpire || !h[0].Applied || !h[0].Current {
		t.Fatalf("historique %+v, %v", h, err)
	}
}

// TestDecideValidation : saisies refusées, constat d'un autre projet introuvable.
func TestDecideValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := e.newOrg("valid")
	f.project("api")
	f.project("web")
	fid := f.finding("api", log4jOld, cve)
	today := e.clock.Now()
	cases := []struct {
		name string
		in   triage.Input
		key  string
	}{
		{"statut inconnu", triage.Input{Status: "open", Comment: "x"}, triage.KeyStatusInvalid},
		{"commentaire absent", triage.Input{Status: triage.StatusAffected, Comment: "  "}, triage.KeyCommentRequired},
		{"commentaire trop long", triage.Input{Status: triage.StatusAffected, Comment: string(make([]byte, triage.MaxComment+1))}, triage.KeyCommentTooLong},
		{"justification inconnue", triage.Input{Status: triage.StatusNotAffected, Comment: "x", Justification: "because"}, triage.KeyJustificationInvalid},
		{"justification hors non affecté", triage.Input{Status: triage.StatusAffected, Comment: "x", Justification: triage.JustCodeNotPresent}, triage.KeyJustificationUnused},
		{"échéance absente", triage.Input{Status: triage.StatusRiskAccepted, Comment: "x"}, triage.KeyExpiryRequired},
		{"échéance passée", triage.Input{Status: triage.StatusRiskAccepted, Comment: "x", ExpiresOn: date(today.AddDate(0, 0, -1))}, triage.KeyExpiryInvalid},
		{"échéance lointaine", triage.Input{Status: triage.StatusRiskAccepted, Comment: "x", ExpiresOn: date(today.AddDate(4, 0, 0))}, triage.KeyExpiryInvalid},
		{"échéance hors risque accepté", triage.Input{Status: triage.StatusFixed, Comment: "x", ExpiresOn: date(today)}, triage.KeyExpiryUnused},
		{"plage pour un projet", triage.Input{Status: triage.StatusFixed, Comment: "x", Vers: "vers:maven/<3"}, triage.KeyVersUnused},
		{"portée inconnue", triage.Input{Scope: "team", Status: triage.StatusFixed, Comment: "x"}, triage.KeyScopeInvalid},
	}
	for _, c := range cases {
		c.in.ProjectID, c.in.FindingID = f.id("api"), fid
		if c.in.Scope == "" {
			c.in.Scope = triage.ScopeProject
		}
		_, _, err := e.svc.Decide(context.Background(), f.org, e.actor, c.in)
		if v, ok := account.IsValidation(err); !ok || v.Key != c.key {
			t.Errorf("%s : %v, attendu %s", c.name, err, c.key)
		}
	}
	_, _, err := e.svc.Decide(context.Background(), f.org, e.actor, triage.Input{ProjectID: f.id("web"), FindingID: fid,
		Scope: triage.ScopeProject, Status: triage.StatusFixed, Comment: "x"})
	if !errors.Is(err, triage.ErrNotFound) {
		t.Fatalf("constat d'un autre projet : %v", err)
	}
	if n := f.count(`SELECT count(*) FROM triage_decisions`); n != 0 {
		t.Fatalf("%d décisions enregistrées malgré les refus", n)
	}
}

// TestTriageIsolation : une organisation ne voit ni ne touche les décisions ni les
// constats d'une autre.
func TestTriageIsolation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.newOrg("a")
	b := e.newOrg("b")
	a.project("api")
	b.project("api")
	fa := a.finding("api", log4jOld, cve)
	fb := b.finding("api", log4jOld, cve)
	d := a.decide(triage.Input{ProjectID: a.id("api"), FindingID: fa, Scope: triage.ScopeOrg, Status: triage.StatusFixed})
	if b.status(fb) != triage.StatusInTriage {
		t.Fatalf("décision de A appliquée à B : %s", b.status(fb))
	}
	if _, _, err := e.svc.Decide(context.Background(), b.org, e.actor, triage.Input{ProjectID: a.id("api"), FindingID: fa,
		Scope: triage.ScopeProject, Status: triage.StatusFixed, Comment: "x"}); !errors.Is(err, triage.ErrNotFound) {
		t.Fatalf("constat de A depuis B : %v", err)
	}
	if _, _, err := e.svc.Withdraw(context.Background(), b.org, e.actor, d.ID, uuid.Nil); !errors.Is(err, triage.ErrNotFound) {
		t.Fatalf("retrait d'une décision de A depuis B : %v", err)
	}
	if ds, err := e.svc.OrgDecisions(context.Background(), b.org); err != nil || len(ds) != 0 {
		t.Fatalf("décisions de B : %+v, %v", ds, err)
	}
	if _, err := e.svc.History(context.Background(), b.org, a.id("api"), fa); !errors.Is(err, triage.ErrNotFound) {
		t.Fatalf("historique d'un constat de A depuis B : %v", err)
	}
	if st, err := e.svc.Statements(context.Background(), b.org, a.id("api")); err != nil || len(st) != 0 {
		t.Fatalf("export d'un projet de A depuis B : %+v, %v", st, err)
	}
}

// TestVEXRoundTripRestoresDecisions : export d'un projet puis import dans le même format
// redonne les mêmes décisions, justifications comprises.
func TestVEXRoundTripRestoresDecisions(t *testing.T) {
	t.Parallel()
	until := date(time.Now().AddDate(0, 2, 0))
	for _, format := range vex.Formats() {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			f := e.newOrg("vex")
			f.project("api")
			ids := map[string]uuid.UUID{}
			want := map[string]triage.Decision{}
			for _, c := range []struct {
				purl, vuln string
				in         triage.Input
			}{
				{log4jOld, cve, triage.Input{Status: triage.StatusNotAffected, Justification: triage.JustProtectedAtRuntime, Comment: "Drapeau JVM."}},
				{log4jOld, "CVE-2099-0001", triage.Input{Status: triage.StatusRiskAccepted, ExpiresOn: until, Comment: "Réseau isolé."}},
				{"pkg:npm/lodash@4.17.20", cve, triage.Input{Status: triage.StatusFalsePositive, Comment: "Pas lodash."}},
				{"pkg:npm/lodash@4.17.20", "CVE-2099-0001", triage.Input{Status: triage.StatusNotAffected,
					Justification: triage.JustInlineMitigationsAlreadyExist, Comment: "WAF."}},
				{"pkg:npm/express@4.0.0", cve, triage.Input{Status: triage.StatusAffected, Comment: "Correctif en 4.2."}},
				{"pkg:npm/express@4.0.0", "CVE-2099-0001", triage.Input{Status: triage.StatusFixed, Comment: "Rétroporté."}},
			} {
				fid := f.finding("api", c.purl, c.vuln)
				ids[c.purl+"|"+c.vuln] = fid
				c.in.ProjectID, c.in.FindingID, c.in.Scope = f.id("api"), fid, triage.ScopeProject
				want[c.purl+"|"+c.vuln] = f.decide(c.in)
			}
			data, err := vex.Export(context.Background(), e.svc, f.org, f.id("api"), format, vex.Meta{Author: "Org", Tooling: "lotor test"})
			if err != nil {
				t.Fatal(err)
			}
			doc, err := vex.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Statements) != 6 {
				t.Fatalf("%d déclarations exportées, attendu 6", len(doc.Statements))
			}
			// Les décisions changent entre-temps ; l'import les rétablit.
			for k, fid := range ids {
				f.decide(triage.Input{ProjectID: f.id("api"), FindingID: fid, Scope: triage.ScopeProject, Status: triage.StatusInTriage,
					Comment: "Remis à analyser " + k})
			}
			res, err := e.svc.Import(context.Background(), f.org, e.actor, triage.ImportInput{Scope: triage.ScopeProject,
				ProjectID: f.id("api"), Source: doc.Author, Format: string(doc.Format), Statements: doc.Statements})
			if err != nil {
				t.Fatal(err)
			}
			if res.Decisions != 6 || res.Ignored != 0 || res.Changed != 6 {
				t.Fatalf("import %+v", res)
			}
			for k, fid := range ids {
				h, err := e.svc.History(context.Background(), f.org, f.id("api"), fid)
				if err != nil || len(h) == 0 {
					t.Fatalf("%s : %v", k, err)
				}
				got, w := h[0].Decision, want[k]
				if !h[0].Applied || got.AuthorLabel != "vex:Org" || got.AuthorUserID != e.user || got.Status != w.Status ||
					got.Justification != w.Justification || got.Comment != w.Comment || !sameDate(got.ExpiresOn, w.ExpiresOn) {
					t.Errorf("%s : %+v\nattendu %+v", k, got, w)
				}
				if f.status(fid) != w.Status {
					t.Errorf("%s : statut %s", k, f.status(fid))
				}
			}
			if n := f.count(`SELECT count(*) FROM audit_events WHERE action = 'triage.vex_imported'`); n != 1 {
				t.Fatalf("%d événements d'import", n)
			}
			if n := f.count(`SELECT count(*) FROM jobs WHERE kind = $1`, triage.ExpireKind); n != 2 {
				t.Fatalf("%d échéances en file, attendu 2 (décision et import)", n)
			}
		})
	}
}

func sameDate(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// TestImportVendorVEX : VEX d'éditeur importé pour l'organisation (famille, version
// déclarée en plage exacte, produit sans version : toutes) et pour un projet (composants
// de ses constats, qualificatifs compatibles, déclarations sans composant écartées).
func TestImportVendorVEX(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := e.newOrg("vendor")
	f.project("api")
	f.project("web")
	old := f.finding("api", log4jOld, cve)
	recent := f.finding("web", log4jNew, cve)
	lodash := f.finding("web", "pkg:npm/lodash@4.17.20", "CVE-2099-0001")
	stmts := []triage.Statement{
		{VulnID: cve, PURL: log4jOld, Status: triage.StatusNotAffected, Justification: triage.JustVulnerableCodeNotInExecPath,
			Comment: "JNDI désactivé."},
		{VulnID: "CVE-2099-0001", PURL: "pkg:npm/lodash", Status: triage.StatusAffected, Comment: "Mettre à jour."},
		{VulnID: "CVE-2099-0002", PURL: "not a purl", Status: triage.StatusFixed},
	}
	res, err := e.svc.Import(context.Background(), f.org, e.actor, triage.ImportInput{Scope: triage.ScopeOrg, Source: " Vendor  Example ",
		Format: "openvex", Statements: stmts})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decisions != 2 || res.Ignored != 1 || res.Changed != 2 {
		t.Fatalf("import d'organisation %+v", res)
	}
	if f.status(old) != triage.StatusNotAffected || f.status(recent) != triage.StatusInTriage || f.status(lodash) != triage.StatusAffected {
		t.Fatalf("2.14.1 %s, 2.17.1 %s, lodash %s", f.status(old), f.status(recent), f.status(lodash))
	}
	if n := f.count(`SELECT count(*) FROM triage_decisions WHERE author_label = 'vex:Vendor Example' AND vers = 'vers:maven/2.14.1'`); n != 1 {
		t.Fatalf("plage exacte absente (%d)", n)
	}
	// Pour un projet : la déclaration sans version vise les composants de la famille ; une
	// déclaration pour un composant absent du projet est écartée.
	res, err = e.svc.Import(context.Background(), f.org, e.actor, triage.ImportInput{Scope: triage.ScopeProject,
		ProjectID: f.id("web"), Source: "Autre", Format: "cyclonedx", Statements: []triage.Statement{
			{VulnID: cve, PURL: log4jBase, Status: triage.StatusFixed},
			{VulnID: cve, PURL: "pkg:npm/absent@1.0.0", Status: triage.StatusFixed},
			{VulnID: "CVE-2099-0001", PURL: "pkg:npm/lodash@4.17.20?arch=x86", Status: triage.StatusFixed},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decisions != 1 || res.Ignored != 2 {
		t.Fatalf("import de projet %+v", res)
	}
	if f.status(recent) != triage.StatusFixed || f.status(old) != triage.StatusNotAffected {
		t.Fatalf("web 2.17.1 %s, api 2.14.1 %s", f.status(recent), f.status(old))
	}
	for name, in := range map[string]triage.ImportInput{
		"source vide":  {Scope: triage.ScopeOrg, Source: " ", Statements: stmts},
		"sans contenu": {Scope: triage.ScopeOrg, Source: "x"},
		"projet nul":   {Scope: triage.ScopeProject, Source: "x", Statements: stmts},
	} {
		if _, err := e.svc.Import(context.Background(), f.org, e.actor, in); err == nil {
			t.Errorf("%s : import accepté", name)
		}
	}
}
