//go:build integration

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

// snapshotIDs renvoie les instantanés d'un projet, du plus ancien au plus récent.
func (a *app) snapshotIDs(org tenant.OrgID, projectID uuid.UUID) []string {
	a.t.Helper()
	var out []string
	if err := a.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(context.Background(), `SELECT id FROM snapshots WHERE project_id = $1 ORDER BY scanned_at, id`, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id.String())
		}
		return rows.Err()
	}); err != nil {
		a.t.Fatal(err)
	}
	return out
}

// TestSnapshotComparisonScreensAndAPI : la frise affiche les changements depuis le
// précédent, la comparaison liste les changements et l'effet sur la sécurité (montée de
// log4j-core qui résout la CVE), à l'identique dans l'API ; accessibilité, deux langues,
// erreurs, et 404 pour un compte qui ne voit pas le projet.
func TestSnapshotComparisonScreensAndAPI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin, reader, outsider := a.user("admin@example.org", false), a.user("reader@example.org", false), a.user("outsider@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	a.addTeamMember(f.org, reader, tenant.TeamReader)
	other, err := a.orgs.CreateTeam(ctx, audit.System, f.org.ID, "Autre")
	if err != nil {
		t.Fatal(err)
	}
	a.addMember(f.org, outsider, tenant.RoleMember)
	if err := a.orgs.AddTeamMember(ctx, audit.System, f.org.ID, other.ID, outsider.Email, tenant.TeamAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := a.projects.Create(ctx, audit.System, f.org.ID, project.Input{Kind: project.KindRepo, Name: "Autre dépôt",
		Branches: []string{"main"}, TeamID: other.ID}); err != nil {
		t.Fatal(err)
	}
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	ref := a.mainRef(f.org.ID, f.p.ID)
	original := sbomFile(t, "log4shell.cdx16.json")
	a.pushLog4shell(f, 1, original)
	if _, err := s.analyzer.Analyze(ctx, f.org.ID, ref); err != nil {
		t.Fatal(err)
	}
	// log4j-core est le premier composant : son champ version précède celui de log4j-api.
	upgraded := bytes.Replace(bytes.ReplaceAll(original, []byte("log4j-core@2.14.1"), []byte("log4j-core@2.17.1")),
		[]byte(`"version": "2.14.1"`), []byte(`"version": "2.17.1"`), 1)
	a.pushLog4shell(f, 2, upgraded)
	if _, err := s.analyzer.Analyze(ctx, f.org.ID, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := a.history.ComputeMissing(ctx, f.org.ID, ref); err != nil {
		t.Fatal(err)
	}
	ids := a.snapshotIDs(f.org.ID, f.p.ID)
	if len(ids) != 2 {
		t.Fatalf("%d instantanés", len(ids))
	}
	base := "/o/org-a/projects/" + f.p.Slug
	compare := base + "/compare?to=" + ids[1]

	for _, u := range []user{admin, reader} {
		b := a.signIn(u)
		for _, lang := range []string{"fr", "en"} {
			for _, path := range []string{base + "/snapshots", compare, compare + "&kind=upgraded", base + "/compare?to=" + ids[0],
				base + "/compare?from=" + ids[1] + "&to=" + ids[0], base + "/snapshots/" + ids[1]} {
				pg := b.get(path + "&lang=" + lang)
				if !strings.Contains(path, "?") {
					pg = b.get(path + "?lang=" + lang)
				}
				if pg.status != http.StatusOK {
					t.Fatalf("%s (%s) : %d", path, lang, pg.status)
				}
				webtest.AssertAccessible(t, []byte(pg.body))
				webtest.AssertNoInlineCode(t, []byte(pg.body))
			}
		}
	}
	b := a.signIn(admin)
	frise := unescape(b.get(base + "/snapshots").body)
	for _, want := range []string{"1 monté de version", "Comparer avec le précédent", base + "/compare?to=" + ids[1], "Comparer deux instantanés",
		"puis le dernier de chaque mois"} {
		if !strings.Contains(frise, want) {
			t.Errorf("frise : %q absent", want)
		}
	}
	pg := unescape(b.get(compare).body)
	resolved := pg[strings.Index(pg, "Constats résolus"):strings.Index(pg, "Constats introduits")]
	if !strings.Contains(resolved, "CVE-2021-44228") {
		t.Errorf("la CVE corrigée par la montée doit figurer parmi les constats résolus")
	}
	for _, want := range []string{"Monté de version", "2.14.1", "2.17.1", "Aucun constat introduit par ce passage."} {
		if !strings.Contains(pg, want) {
			t.Errorf("comparaison : %q absent", want)
		}
	}
	if first := unescape(b.get(base + "/compare?to=" + ids[0]).body); !strings.Contains(first, "Aucun instantané précédent") {
		t.Error("premier instantané : avertissement absent")
	}
	if back := unescape(b.get(base + "/compare?from=" + ids[1] + "&to=" + ids[0]).body); !strings.Contains(back, "Descendu de version") ||
		!strings.Contains(back[strings.Index(back, "Constats introduits"):], "CVE-2021-44228") {
		t.Error("comparaison inverse : descente et CVE introduite attendues")
	}
	for path, want := range map[string]int{
		compare + "&kind=moved":                  http.StatusBadRequest,
		compare + "&cursor=illisible":            http.StatusBadRequest,
		base + "/compare":                        http.StatusNotFound,
		base + "/compare?to=pas-un-uuid":         http.StatusNotFound,
		base + "/compare?to=" + uuid.NewString(): http.StatusNotFound,
		compare + "&from=" + uuid.NewString():    http.StatusNotFound,
	} {
		if p := b.get(path); p.status != want {
			t.Errorf("%s : %d, attendu %d", path, p.status, want)
		}
	}
	// Un membre d'une autre équipe ne voit ni la frise ni la comparaison.
	ob := a.signIn(outsider)
	for _, path := range []string{base + "/snapshots", compare} {
		if p := ob.get(path); p.status != http.StatusNotFound {
			t.Errorf("hors équipe : %s %d", path, p.status)
		}
	}

	// API : mêmes données.
	_, pat, err := a.accounts.CreatePersonalToken(ctx, audit.System, reader.ID, "script", 30)
	if err != nil {
		t.Fatal(err)
	}
	api := "/api/v1/orgs/org-a/projects/" + f.p.Slug
	r := a.apiGet(pat.Plaintext, api+"/snapshots?limit=1")
	var list struct {
		Snapshots []struct {
			ID         string         `json:"id"`
			PreviousID string         `json:"previous_id"`
			Changes    map[string]int `json:"changes"`
		} `json:"snapshots"`
		Page struct {
			NextCursor *string `json:"next_cursor"`
		} `json:"page"`
	}
	if r.status != http.StatusOK || json.Unmarshal([]byte(r.body), &list) != nil || len(list.Snapshots) != 1 || list.Page.NextCursor == nil {
		t.Fatalf("frise de l'API : %d %s", r.status, r.body)
	}
	if s := list.Snapshots[0]; s.ID != ids[1] || s.PreviousID != ids[0] || s.Changes["upgraded"] != 1 || s.Changes["added"] != 0 {
		t.Fatalf("instantané de l'API : %+v", s)
	}
	r = a.apiGet(pat.Plaintext, api+"/compare?to="+ids[1])
	var cmp struct {
		Counts  map[string]int `json:"counts"`
		Changes []struct {
			Kind string `json:"kind"`
			Old  struct {
				Version string `json:"version"`
			} `json:"old"`
			New struct {
				Version string `json:"version"`
			} `json:"new"`
		} `json:"changes"`
		Security struct {
			ResolvedTotal int `json:"resolved_total"`
			Resolved      []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"resolved"`
			Introduced []any `json:"introduced"`
		} `json:"security"`
	}
	if r.status != http.StatusOK || json.Unmarshal([]byte(r.body), &cmp) != nil {
		t.Fatalf("comparaison de l'API : %d %s", r.status, r.body)
	}
	if cmp.Counts["upgraded"] != 1 || len(cmp.Changes) != 1 || cmp.Changes[0].Kind != "upgraded" || cmp.Changes[0].Old.Version != "2.14.1" ||
		cmp.Changes[0].New.Version != "2.17.1" {
		t.Fatalf("changements de l'API : %+v", cmp)
	}
	if cmp.Security.ResolvedTotal != 1 || cmp.Security.Resolved[0].Vulnerability != "CVE-2021-44228" || cmp.Security.Introduced == nil {
		t.Fatalf("effet de l'API : %+v", cmp.Security)
	}
	for path, want := range map[string]string{
		api + "/compare?to=" + ids[0]:                  "error.diff.no_previous",
		api + "/compare?to=" + ids[1] + "&kind=x":      "error.diff.kind_invalid",
		api + "/compare?to=" + uuid.NewString():        "error.not_found",
		api + "/snapshots?cursor=illisible":            "error.invalid_cursor",
		api + "/compare?to=pas-un-uuid":                "error.invalid_request",
		"/api/v1/orgs/org-a/projects/absent/snapshots": "error.not_found",
	} {
		if r := a.apiGet(pat.Plaintext, path); !strings.Contains(r.body, `"type":"`+want+`"`) {
			t.Errorf("%s : %d %s, attendu %s", path, r.status, r.body, want)
		}
	}
	_, opat, err := a.accounts.CreatePersonalToken(ctx, audit.System, outsider.ID, "script", 30)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{api + "/snapshots", api + "/compare?to=" + ids[1]} {
		if r := a.apiGet(opat.Plaintext, path); r.status != http.StatusNotFound {
			t.Errorf("API hors équipe : %s %d", path, r.status)
		}
	}
}
