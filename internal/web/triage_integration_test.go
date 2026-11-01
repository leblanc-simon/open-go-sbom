//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage/vex"
	"leblanc.io/lotor/internal/web/webtest"
)

// uploadTo envoie un formulaire multipart à path, jeton CSRF en tête.
func (b *browser) uploadTo(path string, parts ...uploadPart) page {
	b.t.Helper()
	body, ctype := multipartBody(b.t, append([]uploadPart{{name: "csrf_token", value: b.csrf()}}, parts...)...)
	req, err := http.NewRequest(http.MethodPost, b.app.srv.URL+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", ctype)
	return b.do(req)
}

func (a *app) findingID(org tenant.OrgID, projectID uuid.UUID, vulnID string) uuid.UUID {
	a.t.Helper()
	var id uuid.UUID
	if err := a.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT id FROM findings WHERE project_id = $1 AND vuln_id = $2`,
			projectID, vulnID).Scan(&id)
	}); err != nil {
		a.t.Fatal(err)
	}
	return id
}

func (a *app) triageStatus(org tenant.OrgID, findingID uuid.UUID) string {
	a.t.Helper()
	var s string
	if err := a.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT triage_status FROM findings WHERE id = $1`, findingID).Scan(&s)
	}); err != nil {
		a.t.Fatal(err)
	}
	return s
}

// TestTriageScreens : fiche d'un constat (deux langues, accessibilité, CSP), décision
// d'un analyste, refus d'un lecteur (403) et de la portée organisation sans le droit
// (403), masquage par défaut des non affectés, retrait avec confirmation, historique,
// page VEX (export valide, import), décisions de l'organisation, API, isolement.
func TestTriageScreens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	analyst, reader := a.user("analyst@example.org", false), a.user("reader@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	a.addTeamMember(f.org, analyst, tenant.TeamAnalyst)
	a.addTeamMember(f.org, reader, tenant.TeamReader)
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	a.pushLog4shell(f, 1, sbomFile(t, "log4shell.cdx16.json"))
	if out, err := s.analyzer.Analyze(ctx, f.org.ID, a.mainRef(f.org.ID, f.p.ID)); err != nil || out != finding.OutcomeAnalyzed {
		t.Fatalf("analyse : %s, %v", out, err)
	}
	log4shell := a.findingID(f.org.ID, f.p.ID, "CVE-2021-44228")
	api := a.findingID(f.org.ID, f.p.ID, "CVE-2099-0002")
	base := "/o/org-a/projects/" + f.p.Slug
	page := base + "/findings/" + log4shell.String()
	action := page + "/triage"

	// Un lecteur voit la fiche, sans panneau, et ne peut pas trier.
	rb := a.signIn(reader)
	rp := unescape(rb.get(page).body)
	if !regexp.MustCompile(`<dt>État</dt>\s*<dd>Ouvert</dd>`).MatchString(rp) {
		t.Error("fiche du constat : état « Ouvert » attendu (au singulier)")
	}
	// RGAA 8.6 : la même vulnérabilité sur le même composant d'un autre projet ou d'une
	// autre référence ne donne pas le même titre.
	if got := pageTitle(t, rb.get(page).body); got != "CVE-2021-44228 sur log4j-core — Portail client (main) — Org org-a · lotor" {
		t.Errorf("titre de la fiche du constat : %q", got)
	}
	if !strings.Contains(rp, "CVE-2021-44228") || strings.Contains(rp, `action="`+action+`"`) || !strings.Contains(rp, "ne permet pas de trier") {
		t.Fatal("fiche d'un lecteur")
	}
	if p := rb.post(action, url.Values{"status": {"affected"}, "scope": {"project"}, "comment": {"x"}}); p.status != http.StatusForbidden {
		t.Fatalf("décision d'un lecteur : %d", p.status)
	}

	// Un analyste trie pour le projet, pas pour l'organisation.
	ab := a.signIn(analyst)
	if p := ab.post(action, url.Values{"status": {"not_affected"}, "scope": {"org"}, "justification": {"code_not_reachable"},
		"comment": {"x"}}); p.status != http.StatusForbidden {
		t.Fatalf("décision d'organisation par un analyste : %d", p.status)
	}
	if p := ab.post(action, url.Values{"status": {"not_affected"}, "scope": {"project"}, "comment": {"Greffon non chargé."}}); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(unescape(p.body), "La justification VEX est obligatoire") {
		t.Fatalf("non affecté sans justification : %d", p.status)
	}
	if p := ab.post(action, url.Values{"status": {"risk_accepted"}, "scope": {"project"}, "comment": {"x"}, "expires_on": {"demain"}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("date illisible : %d", p.status)
	}
	p := ab.post(action, url.Values{"status": {"not_affected"}, "scope": {"project"}, "justification": {"code_not_reachable"},
		"comment": {"Le greffon « audit » n'est pas chargé."}})
	if p.status != http.StatusSeeOther || p.location != page+"?done=triage_saved" {
		t.Fatalf("décision : %d %s %s", p.status, p.location, p.body)
	}
	if got := a.triageStatus(f.org.ID, log4shell); got != "not_affected" {
		t.Fatalf("statut %s", got)
	}
	var n int
	if err := a.tdb.App.InOrg(ctx, f.org.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = 'triage.decided'`).Scan(&n)
	}); err != nil || n != 1 {
		t.Fatalf("%d événements d'audit, %v", n, err)
	}

	// Écrans : deux langues, accessibilité, aucune ligne de code en ligne.
	pages := []string{page, page + "?done=triage_saved", base + "/findings", base + "/findings?triage=all",
		base + "/findings?triage=not_affected", base + "/vex", "/o/org-a/vulnerabilities/CVE-2021-44228"}
	for _, u := range []struct {
		b     *browser
		pages []string
	}{{ab, pages}, {rb, pages}, {a.signIn(admin), append(pages, "/o/org-a/triage")}} {
		for _, lang := range []string{"fr", "en"} {
			for _, path := range u.pages {
				sep := "?"
				if strings.Contains(path, "?") {
					sep = "&"
				}
				pg := u.b.get(path + sep + "lang=" + lang)
				if pg.status != http.StatusOK {
					t.Fatalf("%s (%s) : %d %s", path, lang, pg.status, pg.body)
				}
				webtest.AssertAccessible(t, []byte(pg.body))
				webtest.AssertNoInlineCode(t, []byte(pg.body))
			}
		}
	}
	fp := unescape(ab.get(page).body)
	for _, want := range []string{"Non affecté", "décision du projet", "analyst@example.org", "a décidé", "Code non atteignable",
		"Le greffon « audit » n'est pas chargé.", "a ouvert le constat", "/decisions/"} {
		if !strings.Contains(fp, want) {
			t.Errorf("fiche du constat sans %q", want)
		}
	}
	// Masqué par défaut de l'onglet des constats, visible sur demande.
	tab := unescape(ab.get(base + "/findings").body)
	if strings.Contains(tab, "CVE-2021-44228") || !strings.Contains(tab, "1 constat non affecté ou faux positif masqué.") {
		t.Error("constat non affecté affiché par défaut")
	}
	if all := unescape(ab.get(base + "/findings?triage=all").body); !strings.Contains(all, "CVE-2021-44228") || !strings.Contains(all, "Non affecté") {
		t.Error("filtre « tous les statuts »")
	}
	if only := unescape(ab.get(base + "/findings?triage=affected").body); strings.Contains(only, "CVE-2021-44228") {
		t.Error("filtre par statut")
	}

	// L'administrateur de l'organisation décide pour toute l'organisation ; le projet garde
	// sa décision.
	adm := a.signIn(admin)
	apiPage := base + "/findings/" + api.String()
	if p := adm.post(apiPage+"/triage", url.Values{"status": {"affected"}, "scope": {"org"}, "comment": {"À corriger partout."},
		"vers": {"vers:maven/<2.17.0"}}); p.status != http.StatusSeeOther {
		t.Fatalf("décision d'organisation : %d %s", p.status, unescape(p.body))
	}
	if a.triageStatus(f.org.ID, api) != "affected" || a.triageStatus(f.org.ID, log4shell) != "not_affected" {
		t.Fatal("décision d'organisation mal appliquée")
	}
	op := unescape(adm.get("/o/org-a/triage").body)
	if !strings.Contains(op, "pkg:maven/org.apache.logging.log4j/log4j-api") || !strings.Contains(op, "vers:maven/<2.17.0") {
		t.Error("liste des décisions de l'organisation")
	}
	if p := ab.get("/o/org-a/triage"); p.status != http.StatusForbidden {
		t.Errorf("décisions de l'organisation pour un analyste : %d", p.status)
	}

	// Retrait de la décision du projet : confirmation, puis retour à « à analyser ».
	hs, err := a.triage.History(ctx, f.org.ID, f.p.ID, log4shell)
	if err != nil || len(hs) != 1 {
		t.Fatalf("historique %+v, %v", hs, err)
	}
	withdraw := base + "/decisions/" + hs[0].ID.String() + "/withdraw"
	if c := ab.get(withdraw); c.status != http.StatusOK || !strings.Contains(unescape(c.body), "Retirer la décision « Non affecté » sur CVE-2021-44228 ?") {
		t.Fatalf("confirmation : %d", c.status)
	}
	if c := ab.get(withdraw + "?lang=en"); !strings.Contains(unescape(c.body), "Withdraw the “Not affected” decision on CVE-2021-44228?") {
		t.Error("confirmation (en) : statut non traduit")
	}
	if p := rb.post(withdraw, nil); p.status != http.StatusForbidden {
		t.Fatalf("retrait par un lecteur : %d", p.status)
	}
	if p := ab.post(withdraw, nil); p.status != http.StatusSeeOther {
		t.Fatalf("retrait : %d", p.status)
	}
	if a.triageStatus(f.org.ID, log4shell) != "in_triage" {
		t.Fatal("après retrait")
	}
	if p := ab.post(withdraw, nil); p.status != http.StatusNotFound {
		t.Fatalf("second retrait : %d", p.status)
	}

	// VEX : export OpenVEX et CycloneDX valides, import pour le projet.
	p = ab.post(action, url.Values{"status": {"risk_accepted"}, "scope": {"project"}, "comment": {"Réseau isolé."},
		"expires_on": {time.Now().UTC().AddDate(0, 1, 0).Format(time.DateOnly)}})
	if p.status != http.StatusSeeOther {
		t.Fatalf("risque accepté : %d %s", p.status, unescape(p.body))
	}
	ov, err := vex.NewOpenVEXValidator()
	if err != nil {
		t.Fatal(err)
	}
	oe := ab.get(base + "/vex/export?format=openvex")
	if oe.status != http.StatusOK || !strings.Contains(oe.header.Get("Content-Disposition"), "openvex.json") {
		t.Fatalf("export OpenVEX : %d", oe.status)
	}
	if err := ov.Validate([]byte(oe.body)); err != nil {
		t.Fatalf("OpenVEX invalide : %v", err)
	}
	ce := ab.get(base + "/vex/export?format=cyclonedx")
	if ce.status != http.StatusOK || ce.header.Get("Content-Type") != "application/vnd.cyclonedx+json" {
		t.Fatalf("export CycloneDX : %d", ce.status)
	}
	if err := testValidator(t).ValidateStrict(sbom.FormatCycloneDX, "1.6", []byte(ce.body)); err != nil {
		t.Fatalf("CycloneDX invalide : %v", err)
	}
	if bad := ab.get(base + "/vex/export?format=csaf"); bad.status != http.StatusBadRequest {
		t.Errorf("format inconnu : %d", bad.status)
	}
	// Retour à « à analyser », puis réimport de l'export : la décision revient.
	ab.post(action, url.Values{"status": {"in_triage"}, "scope": {"project"}, "comment": {"À revoir."}})
	imp := ab.uploadTo(base+"/vex/import", uploadPart{name: "file", file: "export.json", value: oe.body}, uploadPart{name: "source", value: ""})
	if imp.status != http.StatusOK || !strings.Contains(unescape(imp.body), "2 décisions enregistrées.") {
		t.Fatalf("import : %d %s", imp.status, unescape(imp.body))
	}
	if a.triageStatus(f.org.ID, log4shell) != "risk_accepted" {
		t.Fatal("import sans effet")
	}
	if bad := ab.uploadTo(base+"/vex/import", uploadPart{name: "file", file: "x.json", value: "{}"}); bad.status != http.StatusUnprocessableEntity {
		t.Errorf("document illisible : %d", bad.status)
	}
	if big := ab.uploadTo(base+"/vex/import", uploadPart{name: "file", file: "x.json", value: strings.Repeat(" ", vex.MaxDocument+1)}); big.status != http.StatusRequestEntityTooLarge &&
		big.status != http.StatusUnprocessableEntity {
		t.Errorf("document trop gros : %d", big.status)
	}
	if p := rb.uploadTo(base+"/vex/import", uploadPart{name: "file", file: "export.json", value: oe.body}); p.status != http.StatusForbidden {
		t.Errorf("import par un lecteur : %d", p.status)
	}
	if p := ab.uploadTo("/o/org-a/triage/import", uploadPart{name: "file", file: "export.json", value: oe.body}); p.status != http.StatusForbidden {
		t.Errorf("import d'organisation par un analyste : %d", p.status)
	}
	if p := adm.uploadTo("/o/org-a/triage/import", uploadPart{name: "file", file: "export.json", value: oe.body},
		uploadPart{name: "source", value: "Éditeur"}); p.status != http.StatusOK || !strings.Contains(unescape(p.body), "VEX importé de « Éditeur »") {
		t.Errorf("import d'organisation : %d %s", p.status, unescape(p.body))
	}

	// API utilisateur : même export, projet visible seulement.
	created := ab.post("/account/tokens", url.Values{"name": {"VEX"}, "expires_in": {"30"}, "code": {a.code(analyst.ID, analyst.Secret)}})
	token := patPattern.FindString(created.body)
	if token == "" {
		t.Fatalf("jeton personnel : %d", created.status)
	}
	got := a.apiGet(token, "/api/v1/orgs/org-a/projects/"+f.p.Slug+"/vex?format=openvex")
	if got.status != http.StatusOK || ov.Validate([]byte(got.body)) != nil {
		t.Fatalf("API : %d %s", got.status, got.body)
	}
	if nf := a.apiGet(token, "/api/v1/orgs/org-a/projects/absent/vex?format=openvex"); nf.status != http.StatusNotFound {
		t.Errorf("API, projet absent : %d", nf.status)
	}
	if bad := a.apiGet(token, "/api/v1/orgs/org-a/projects/"+f.p.Slug+"/vex?format=csaf"); bad.status != http.StatusBadRequest {
		t.Errorf("API, format inconnu : %d", bad.status)
	}

	// Une autre organisation : constat et décision de A introuvables, même par un projet
	// de B.
	stranger := a.user("stranger@example.org", false)
	g := repoSetup(t, a, "org-b", stranger)
	sb := a.signIn(stranger)
	for _, path := range []string{page, "/o/org-b/projects/" + g.p.Slug + "/findings/" + log4shell.String(), base + "/vex",
		base + "/vex/export?format=openvex"} {
		if pg := sb.get(path); pg.status != http.StatusNotFound {
			t.Errorf("%s par une autre organisation : %d", path, pg.status)
		}
	}
	orgDecision := hsOrg(t, a, f.org.ID)
	for _, path := range []string{"/o/org-b/triage/decisions/" + orgDecision + "/withdraw",
		"/o/org-b/projects/" + g.p.Slug + "/decisions/" + orgDecision + "/withdraw"} {
		if pg := sb.post(path, nil); pg.status != http.StatusNotFound {
			t.Errorf("POST %s par une autre organisation : %d", path, pg.status)
		}
	}
	if pg := sb.post("/o/org-b/projects/"+g.p.Slug+"/findings/"+log4shell.String()+"/triage",
		url.Values{"status": {"fixed"}, "scope": {"project"}, "comment": {"x"}}); pg.status != http.StatusNotFound {
		t.Errorf("décision sur un constat de A depuis B : %d", pg.status)
	}
	if a.triageStatus(f.org.ID, log4shell) != "risk_accepted" {
		t.Error("constat de A modifié depuis B")
	}
}

// hsOrg renvoie la décision d'organisation courante de org.
func hsOrg(t *testing.T, a *app, org tenant.OrgID) string {
	t.Helper()
	ds, err := a.triage.OrgDecisions(context.Background(), org)
	if err != nil || len(ds) == 0 {
		t.Fatalf("décisions d'organisation : %+v, %v", ds, err)
	}
	return ds[0].ID.String()
}
