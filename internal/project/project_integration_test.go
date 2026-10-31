//go:build integration

package project_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/org"
	"leblanc.io/open-go-sbom/internal/pagination"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/tenant"
)

func isKey(err error, k string) bool {
	v, ok := account.IsValidation(err)
	return ok && v.Key == k
}

type fixture struct {
	tdb      *dbtest.DB
	projects *project.Service
	agents   *agent.Service
	orgs     *org.Service
	actor    audit.Actor
}

func setup(t *testing.T) fixture {
	t.Helper()
	tdb := dbtest.New(t)
	accounts := account.NewService(tdb.App, 4)
	u, _, err := accounts.Create(context.Background(), audit.System, "admin@example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{tdb: tdb, projects: project.NewService(tdb.App), agents: agent.NewService(tdb.App),
		orgs: org.NewService(tdb.App), actor: audit.Actor{UserID: u.ID, Email: u.Email}}
}

func (f fixture) org(t *testing.T, slug string) tenant.OrgID {
	t.Helper()
	o, err := f.orgs.Create(context.Background(), audit.System, slug, "Org "+slug, "fr", f.actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return o.ID
}

func (f fixture) actions(t *testing.T, org tenant.OrgID) []audit.Action {
	t.Helper()
	var out []audit.Action
	err := f.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		page, err := audit.ListOrg(context.Background(), tx, "", 200)
		for _, e := range page.Items {
			out = append(out, e.Action)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func repo(name string, branches ...string) project.Input {
	return project.Input{Kind: project.KindRepo, Name: name, Branches: branches}
}

func TestCreateRepositoryAndHost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")

	p, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindRepo, Name: "Portail Client",
		Description: "Site public", Labels: project.Labels{"env": "prod"}, ForgeURL: "https://git.example.org/web/portail",
		Branches: []string{"main", "release"}, Tags: []string{"v1.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Slug != "portail-client" {
		t.Fatalf("slug %q", p.Slug)
	}
	got, err := f.projects.Get(ctx, o, "portail-client")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != project.KindRepo || got.ForgeURL != "https://git.example.org/web/portail" || got.Labels["env"] != "prod" ||
		!slices.Equal(got.RefNames(project.RefBranch), []string{"main", "release"}) || !slices.Equal(got.RefNames(project.RefTag), []string{"v1.0"}) {
		t.Fatalf("projet relu : %+v", got)
	}

	// Slug dérivé rendu unique ; slug explicite pris ou réservé refusé.
	p2, err := f.projects.Create(ctx, f.actor, o, repo("Portail client", "main"))
	if err != nil || p2.Slug != "portail-client-2" {
		t.Fatalf("second slug : %q %v", p2.Slug, err)
	}
	if _, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindRepo, Slug: "portail-client", Name: "x", Branches: []string{"main"}}); !isKey(err, project.KeySlugTaken) {
		t.Errorf("slug pris : %v", err)
	}
	if _, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindRepo, Slug: "new", Name: "x", Branches: []string{"main"}}); !isKey(err, project.KeySlugInvalid) {
		t.Errorf("slug réservé : %v", err)
	}
	if p3, err := f.projects.Create(ctx, f.actor, o, repo("New", "main")); err != nil || p3.Slug != "new-2" {
		t.Errorf("slug dérivé réservé : %q %v", p3.Slug, err)
	}

	// Serveur : une seule référence d'hôte, unique dans l'organisation.
	h, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "srv-db-02", HostRef: "SRV-DB-02"})
	if err != nil {
		t.Fatal(err)
	}
	if h, err = f.projects.Get(ctx, o, h.Slug); err != nil || h.HostRef() != "srv-db-02" || len(h.Refs) != 1 {
		t.Fatalf("hôte : %+v %v", h, err)
	}
	if _, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "autre", HostRef: "srv-db-02"}); !isKey(err, project.KeyHostRefTaken) {
		t.Errorf("hôte en double : %v", err)
	}
	// Même nom d'hôte dans une autre organisation : permis.
	if _, err := f.projects.Create(ctx, f.actor, f.org(t, "b"), project.Input{Kind: project.KindHost, Name: "srv-db-02", HostRef: "srv-db-02"}); err != nil {
		t.Errorf("hôte dans une autre organisation : %v", err)
	}
	if n := countOf(f.actions(t, o), audit.ProjectCreated); n != 4 {
		t.Errorf("%d créations journalisées", n)
	}
}

func countOf(actions []audit.Action, a audit.Action) int {
	n := 0
	for _, x := range actions {
		if x == a {
			n++
		}
	}
	return n
}

// TestUpdateKeepsRefHistory : une référence retirée garde sa ligne et la réajouter la
// réactive ; la référence d'un hôte est renommée sur place.
func TestUpdateKeepsRefHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, err := f.projects.Create(ctx, f.actor, o, repo("api", "main", "dev"))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := f.projects.Get(ctx, o, p.Slug)
	ids := map[string]uuid.UUID{}
	for _, r := range before.Refs {
		ids[r.Name] = r.ID
	}

	in := repo("API facturation", "main")
	in.Tags, in.Labels = []string{"v2"}, project.Labels{"pci": ""}
	if err := f.projects.Update(ctx, f.actor, o, p.Slug, in); err != nil {
		t.Fatal(err)
	}
	mid, _ := f.projects.Get(ctx, o, p.Slug)
	if mid.Name != "API facturation" || mid.Slug != "api" || !slices.Equal(mid.RefNames(project.RefBranch), []string{"main"}) ||
		!slices.Equal(mid.RefNames(project.RefTag), []string{"v2"}) || mid.Labels.String() != "pci" {
		t.Fatalf("après modification : %+v", mid)
	}
	if err := f.projects.Update(ctx, f.actor, o, p.Slug, repo("API facturation", "main", "dev")); err != nil {
		t.Fatal(err)
	}
	after, _ := f.projects.Get(ctx, o, p.Slug)
	for _, r := range after.Refs {
		if r.Kind == project.RefBranch && r.ID != ids[r.Name] {
			t.Errorf("branche %s : nouvel identifiant après réactivation", r.Name)
		}
	}
	if err := f.projects.Update(ctx, f.actor, o, p.Slug, repo("x")); !isKey(err, project.KeyRefsMissing) {
		t.Errorf("sans référence : %v", err)
	}

	h, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "srv", HostRef: "srv"})
	if err != nil {
		t.Fatal(err)
	}
	h, _ = f.projects.Get(ctx, o, h.Slug)
	if err := f.projects.Update(ctx, f.actor, o, h.Slug, project.Input{Name: "srv", HostRef: "srv.example.org"}); err != nil {
		t.Fatal(err)
	}
	h2, _ := f.projects.Get(ctx, o, h.Slug)
	if h2.HostRef() != "srv.example.org" || h2.Refs[0].ID != h.Refs[0].ID {
		t.Errorf("référence d'hôte : %+v", h2.Refs)
	}
	if err := f.projects.Update(ctx, f.actor, o, "absent", repo("x", "main")); !errors.Is(err, project.ErrNotFound) {
		t.Errorf("projet absent : %v", err)
	}
	if n := countOf(f.actions(t, o), audit.ProjectUpdated); n != 3 {
		t.Errorf("%d modifications journalisées", n)
	}
}

func TestArchiveAndList(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	for _, in := range []project.Input{
		{Kind: project.KindRepo, Name: "Bravo", Labels: project.Labels{"env": "prod"}, Branches: []string{"main"}},
		{Kind: project.KindRepo, Name: "alpha", Labels: project.Labels{"env": "dev", "pci": ""}, Branches: []string{"main"}},
		{Kind: project.KindHost, Name: "charlie_100%", HostRef: "charlie", Labels: project.Labels{"env": "prod"}},
	} {
		if _, err := f.projects.Create(ctx, f.actor, o, in); err != nil {
			t.Fatal(err)
		}
	}
	names := func(fl project.Filter) []string {
		page, err := f.projects.List(ctx, o, fl, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range page.Items {
			out = append(out, p.Name)
		}
		return out
	}
	for _, c := range []struct {
		f    project.Filter
		want []string
	}{
		{project.Filter{}, []string{"alpha", "Bravo", "charlie_100%"}},
		{project.Filter{Kind: project.KindHost}, []string{"charlie_100%"}},
		{project.Filter{Label: "env=prod"}, []string{"Bravo", "charlie_100%"}},
		{project.Filter{Label: "PCI"}, []string{"alpha"}},
		{project.Filter{Query: "RAV"}, []string{"Bravo"}},
		{project.Filter{Query: "%"}, []string{"charlie_100%"}},
		{project.Filter{Query: "_"}, []string{"charlie_100%"}},
	} {
		if got := names(c.f); !slices.Equal(got, c.want) {
			t.Errorf("%+v : %v, attendu %v", c.f, got, c.want)
		}
	}

	// Pagination stable par nom.
	page, err := f.projects.List(ctx, o, project.Filter{}, "", 2)
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("première page : %v %v", page, err)
	}
	next, err := f.projects.List(ctx, o, project.Filter{}, page.NextCursor, 2)
	if err != nil || len(next.Items) != 1 || next.Items[0].Name != "charlie_100%" || next.NextCursor != "" {
		t.Fatalf("seconde page : %v %v", next, err)
	}
	if _, err := f.projects.List(ctx, o, project.Filter{}, "pas-un-curseur", 2); !errors.Is(err, pagination.ErrInvalidCursor) {
		t.Errorf("curseur invalide : %v", err)
	}
	var le *pagination.LimitError
	if _, err := f.projects.List(ctx, o, project.Filter{}, "", 0); !errors.As(err, &le) {
		t.Errorf("taille 0 : %v", err)
	}

	if err := f.projects.SetArchived(ctx, f.actor, o, "bravo", true); err != nil {
		t.Fatal(err)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, "bravo", true); err != nil {
		t.Fatal(err)
	}
	if got := names(project.Filter{}); !slices.Equal(got, []string{"alpha", "charlie_100%"}) {
		t.Errorf("actifs : %v", got)
	}
	if got := names(project.Filter{Archived: true}); !slices.Equal(got, []string{"Bravo"}) {
		t.Errorf("archivés : %v", got)
	}
	if err := f.projects.Update(ctx, f.actor, o, "bravo", repo("x", "main")); !isKey(err, project.KeyProjectArchived) {
		t.Errorf("modification d'un projet archivé : %v", err)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, "bravo", false); err != nil {
		t.Fatal(err)
	}
	acts := f.actions(t, o)
	if countOf(acts, audit.ProjectArchived) != 1 || countOf(acts, audit.ProjectUnarchived) != 1 {
		t.Errorf("journal : %v", acts)
	}
}

// TestAssignAgentRequiresActiveRepoAgent : un dépôt n'est confié qu'à un agent dépôt actif
// de l'organisation ; un serveur ne reçoit pas d'agent depuis l'interface.
func TestAssignAgentRequiresActiveRepoAgent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o, other := f.org(t, "a"), f.org(t, "b")
	p, err := f.projects.Create(ctx, f.actor, o, repo("api", "main"))
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := f.agents.CreateRepoAgent(ctx, f.actor, other, "ci-b", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, p.Slug, &foreign.ID); !isKey(err, project.KeyAgentInvalid) {
		t.Errorf("agent d'une autre organisation : %v", err)
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, p.Slug, &a.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.projects.Get(ctx, o, p.Slug)
	if got.Agent == nil || got.Agent.ID != a.ID || got.Agent.Name != "ci" {
		t.Fatalf("agent : %+v", got.Agent)
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, p.Slug, &a.ID); err != nil {
		t.Fatal(err)
	}
	h, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "srv", HostRef: "srv"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, h.Slug, &a.ID); !isKey(err, project.KeyAgentInvalid) {
		t.Errorf("agent sur un serveur : %v", err)
	}
	if err := f.agents.Disable(ctx, f.actor, o, a.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.projects.Get(ctx, o, p.Slug); got.Agent != nil {
		t.Error("projet encore confié à un agent désactivé")
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, p.Slug, &a.ID); !isKey(err, project.KeyAgentInvalid) {
		t.Errorf("agent désactivé : %v", err)
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, p.Slug, nil); err != nil {
		t.Fatal(err)
	}
	if n := countOf(f.actions(t, o), audit.ProjectAgentChanged); n != 1 {
		t.Errorf("%d affectations journalisées", n)
	}
}

// TestSchemaRefusesMismatchedKinds : les clés étrangères composites refusent un agent
// serveur sur un dépôt, un second hôte par agent serveur et une référence d'hôte sur un
// dépôt, même en SQL direct.
func TestSchemaRefusesMismatchedKinds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	err := f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		host, repoAgent := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		if _, err := tx.ExecContext(ctx, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'host', 'h'), ($1, $3, 'repo', 'r')`,
			tx.OrgID(), host, repoAgent); err != nil {
			return err
		}
		p1, p2 := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		for name, stmt := range map[string]string{
			"agent serveur sur un dépôt": `INSERT INTO projects (org_id, id, kind, slug, name, agent_id) VALUES ($1, gen_random_uuid(), 'repo', 'x', 'x', '` + host.String() + `')`,
			"deux hôtes pour un agent": `INSERT INTO projects (org_id, id, kind, slug, name, agent_id) VALUES
				($1, '` + p1.String() + `', 'host', 'h1', 'h1', '` + host.String() + `'), ($1, '` + p2.String() + `', 'host', 'h2', 'h2', '` + host.String() + `')`,
		} {
			if _, err := tx.ExecContext(ctx, `SAVEPOINT s`); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, stmt, tx.OrgID()); err == nil {
				t.Errorf("%s accepté", name)
			}
			if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT s`); err != nil {
				return err
			}
		}
		repoID := uuid.Must(uuid.NewV7())
		if _, err := tx.ExecContext(ctx, `INSERT INTO projects (org_id, id, kind, slug, name) VALUES ($1, $2, 'repo', 'r', 'r')`, tx.OrgID(), repoID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SAVEPOINT s`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
			VALUES ($1, gen_random_uuid(), $2, 'repo', 'host', 'srv')`, tx.OrgID(), repoID); err == nil {
			t.Error("référence d'hôte sur un dépôt acceptée")
		}
		_, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT s`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAgentView : un agent ne lit que ses projets actifs, page par page, et n'écrit que
// sur leurs références actives.
func TestAgentView(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	a, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	for _, n := range []string{"p1", "p2", "p3"} {
		in := repo(n, "main")
		in.Tags, in.ForgeURL = []string{"v1"}, "https://git.example.org/"+n
		p, err := f.projects.Create(ctx, f.actor, o, in)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.projects.AssignAgent(ctx, f.actor, o, p.Slug, &a.ID); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, p.ID)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, "p2", true); err != nil {
		t.Fatal(err)
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, "p2", nil); !isKey(err, project.KeyProjectArchived) {
		t.Errorf("affectation d'un projet archivé : %v", err)
	}
	err = f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		page, err := project.ListForAgent(ctx, tx, a.ID, "", 1)
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != ids[0] || page.NextCursor == "" || len(page.Items[0].Refs) != 2 {
			t.Fatalf("première page : %+v %v", page, err)
		}
		next, err := project.ListForAgent(ctx, tx, a.ID, page.NextCursor, 10)
		if err != nil || len(next.Items) != 1 || next.Items[0].ID != ids[2] || next.NextCursor != "" {
			t.Fatalf("seconde page : %+v %v", next, err)
		}
		if _, err := project.ListForAgent(ctx, tx, a.ID, "", project.AgentPageMax+1); err == nil {
			t.Error("page trop grande acceptée")
		}
		if _, err := project.ListForAgent(ctx, tx, a.ID, "x", 1); !errors.Is(err, pagination.ErrInvalidCursor) {
			t.Errorf("curseur : %v", err)
		}
		empty, err := project.ListForAgent(ctx, tx, uuid.Must(uuid.NewV7()), "", 10)
		if err != nil || len(empty.Items) != 0 {
			t.Errorf("agent sans projet : %+v %v", empty, err)
		}
		if r, err := project.RefForAgent(ctx, tx, a.ID, ids[0], project.RefTag, "v1"); err != nil || r.ID == uuid.Nil {
			t.Errorf("étiquette suivie : %+v %v", r, err)
		}
		if _, err := project.RefForAgent(ctx, tx, a.ID, ids[1], project.RefBranch, "main"); !errors.Is(err, project.ErrNotFound) {
			t.Errorf("projet archivé : %v", err)
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []func() error{
		func() error { _, err := f.projects.Get(ctx, o, "absent"); return err },
		func() error { return f.projects.SetArchived(ctx, f.actor, o, "absent", true) },
		func() error { return f.projects.AssignAgent(ctx, f.actor, o, "absent", nil) },
	} {
		if err := fn(); !errors.Is(err, project.ErrNotFound) {
			t.Errorf("projet absent : %v", err)
		}
	}
	// Une modification sans changement est journalisée sans champ.
	if err := f.projects.Update(ctx, f.actor, o, "p1", project.Input{Name: "p1", Branches: []string{"main"}, Tags: []string{"v1"},
		ForgeURL: "https://git.example.org/p1"}); err != nil {
		t.Fatal(err)
	}
}
