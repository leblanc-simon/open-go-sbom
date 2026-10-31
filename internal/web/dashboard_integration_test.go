//go:build integration

package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

// TestDashboardScreens : tableau de bord de l'organisation et en-tête de la fiche projet,
// sur des constats produits par l'analyse ; deux langues, deux thèmes, trois périodes,
// accessibilité (graphiques compris), absence de code en ligne, isolement des données.
func TestDashboardScreens(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin, viewer := a.user("admin@example.org", false), a.user("viewer@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	a.addMember(f.org, viewer, tenant.RoleViewer)
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	ctx := context.Background()
	a.pushLog4shell(f, 1, sbomFile(t, "log4shell.cdx16.json"))
	if out, err := s.analyzer.Analyze(ctx, f.org.ID, a.mainRef(f.org.ID, f.p.ID)); err != nil || out != finding.OutcomeAnalyzed {
		t.Fatalf("analyse : %s, %v", out, err)
	}

	b := a.signIn(admin)
	// Premier jour, aucune statistique enregistrée : un seul point par courbe.
	dash := unescape(b.get("/o/org-a").body)
	for _, want := range []string{"Tableau de bord", "Constats ouverts", "Vulnérabilités KEV ouvertes", "1 constat dans 1 projet",
		"pas encore d'historique à 7 jours", "Tendance sur 90 jours", "L'historique commence aujourd'hui", "Délai médian de correction",
		"Projets les plus exposés", "Portail client", "Composants vulnérables les plus répandus", "log4j-core",
		"pkg:maven/org.apache.logging.log4j/log4j-core", "1 projet actif", "1 dépôt", "Dernière analyse de vulnérabilités",
		"Aucun agent muet.", `role="img"`, "Constats ouverts : 1 le "} {
		if !strings.Contains(dash, want) {
			t.Errorf("tableau de bord sans %q", want)
		}
	}

	// Statistiques enregistrées le lendemain ; une semaine plus tard, l'agent est muet
	// (8 jours sans contact).
	a.clock.advance(24 * time.Hour)
	if _, err := a.dash.Record(ctx, f.org.ID); err != nil {
		t.Fatal(err)
	}
	a.clock.advance(7 * 24 * time.Hour)
	week := unescape(b.get("/o/org-a?period=30").body)
	for _, want := range []string{"Tendance sur 30 jours", "stable en 7 jours", "1 sans inventaire ni contact depuis plus de 7 jours", ">ci</a>", "8 j"} {
		if !strings.Contains(week, want) {
			t.Errorf("tableau de bord à J+8 sans %q", want)
		}
	}
	if strings.Contains(week, "L'historique commence aujourd'hui") {
		t.Error("deux points attendus à J+8")
	}

	project := "/o/org-a/projects/" + f.p.Slug
	for _, u := range []user{admin, viewer} {
		ub := a.signIn(u)
		for _, lang := range []string{"fr", "en"} {
			for _, theme := range []string{"light", "dark"} {
				for _, path := range []string{"/o/org-a", "/o/org-a?period=365", "/o/org-a?period=bogus", project, project + "?period=30"} {
					sep := "?"
					if strings.Contains(path, "?") {
						sep = "&"
					}
					req, err := http.NewRequest(http.MethodGet, a.srv.URL+path+sep+"lang="+lang, nil)
					if err != nil {
						t.Fatal(err)
					}
					req.AddCookie(&http.Cookie{Name: render.ThemeCookie, Value: theme})
					pg := ub.do(req)
					if pg.status != http.StatusOK || !strings.Contains(pg.body, `data-theme="`+theme+`"`) {
						t.Fatalf("%s (%s, %s) : %d", path, lang, theme, pg.status)
					}
					webtest.AssertAccessible(t, []byte(pg.body))
					webtest.AssertNoInlineCode(t, []byte(pg.body))
				}
			}
		}
	}
	en := unescape(b.get("/o/org-a?lang=en").body)
	for _, want := range []string{"Dashboard", "Open findings", "Median time to fix", "Most exposed projects", "1 active project"} {
		if !strings.Contains(en, want) {
			t.Errorf("tableau de bord en anglais sans %q", want)
		}
	}
	head := unescape(b.get(project).body)
	for _, want := range []string{"Constats ouverts", "Vulnérabilités KEV ouvertes", "Tendance sur 90 jours", "Délai médian de correction"} {
		if !strings.Contains(head, want) {
			t.Errorf("fiche projet sans %q", want)
		}
	}

	// Une autre organisation ne voit rien de A : ni sur son tableau de bord, ni sur celui
	// de A (404).
	stranger := a.user("stranger@example.org", false)
	a.org("org-b", stranger)
	sb := a.signIn(stranger)
	other := unescape(sb.get("/o/org-b").body)
	for _, leak := range []string{"Portail client", "log4j-core", ">ci<"} {
		if strings.Contains(other, leak) {
			t.Errorf("tableau de bord de B contient %q", leak)
		}
	}
	if !strings.Contains(other, "Aucun projet n'a de constat ouvert.") || !strings.Contains(other, "Aucune analyse de vulnérabilités") {
		t.Error("tableau de bord vide de B")
	}
	for _, path := range []string{"/o/org-a", "/o/org-a?period=30", project} {
		if pg := sb.get(path); pg.status != http.StatusNotFound {
			t.Errorf("%s pour B : %d", path, pg.status)
		}
	}
}
