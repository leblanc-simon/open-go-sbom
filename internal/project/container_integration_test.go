//go:build integration

package project_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// hostWithAgent crée un agent serveur et le projet de son hôte dans l'équipe team.
func (f fixture) hostWithAgent(t *testing.T, org tenant.OrgID, host string, team uuid.UUID) (uuid.UUID, project.Project) {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.Must(uuid.NewV7())
	var p project.Project
	err := f.tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO agents (org_id, id, kind, name, team_id) VALUES ($1, $2, 'host', $3, $4)`,
			tx.OrgID(), agentID, host, team); err != nil {
			return err
		}
		var err error
		p, err = project.CreateHost(ctx, tx, host, nil, agentID, team)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return agentID, p
}

func sighting(key, image string) project.ContainerSighting {
	started := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	c := project.ContainerContext{Engine: project.EngineDocker, Names: []string{key}, Replicas: 1, Image: image,
		ImageID: "sha256:" + strings.Repeat("a", 64), StartedAt: &started}
	return project.ContainerSighting{Key: key, Context: c}
}

// sight signale des conteneurs pour agentID à l'instant now.
func (f fixture) sight(t *testing.T, org tenant.OrgID, agentID uuid.UUID, now time.Time, s ...project.ContainerSighting) ([]project.ChildState, error) {
	t.Helper()
	var out []project.ChildState
	err := f.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		var err error
		out, err = project.SightContainers(context.Background(), tx, audit.Actor{Email: "agent"}, agentID, s, now, project.DefaultMaxContainersPerHost)
		return err
	})
	return out, err
}

// TestContainerChildren : un conteneur signalé devient un projet enfant de l'hôte de
// l'agent, dans son équipe, avec une référence « container » ; le même conteneur ne crée
// rien de plus ; un agent ne crée d'enfant que sous son propre hôte.
func TestContainerChildren(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	team := f.defaultTeam(t, o)
	agentA, hostA := f.hostWithAgent(t, o, "srv-a", team)
	agentB, hostB := f.hostWithAgent(t, o, "srv-b", team)
	now := time.Now().UTC().Round(time.Microsecond)

	states, err := f.sight(t, o, agentA, now, sighting("shop/web", "nginx:1.27"), sighting("redis", "redis:7"))
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[0].Key != "redis" || !states[0].Created || states[1].Key != "shop/web" || states[0].RefID == uuid.Nil {
		t.Fatalf("signalement : %+v", states)
	}
	again, err := f.sight(t, o, agentA, now.Add(time.Hour), sighting("shop/web", "nginx:1.28"))
	if err != nil || again[0].Created || again[0].ProjectID != states[1].ProjectID || again[0].RefID != states[1].RefID {
		t.Fatalf("second signalement : %+v %v", again, err)
	}
	web, err := f.projects.Get(ctx, o, tenant.AllTeams(), states[1].Slug)
	if err != nil {
		t.Fatal(err)
	}
	if web.Kind != project.KindContainer || web.Slug != "srv-a-shop-web" || web.Name != "srv-a/shop/web" || web.TeamID != team ||
		web.Parent == nil || web.Parent.ID != hostA.ID || web.Parent.Slug != "srv-a" || web.Container == nil ||
		web.Container.Key != "shop/web" || web.Container.Context.Image != "nginx:1.28" || !web.Container.SeenAt.Equal(now.Add(time.Hour)) ||
		web.Agent == nil || web.Agent.ID != agentA || len(web.Refs) != 1 || web.Refs[0].Kind != project.RefContainer || web.Refs[0].Name != "shop/web" {
		t.Fatalf("projet enfant : %+v %+v %+v", web, web.Parent, web.Container)
	}
	// Même identité sous un autre hôte : un autre projet, sous cet hôte-là.
	other, err := f.sight(t, o, agentB, now, sighting("redis", "redis:7"))
	if err != nil || other[0].ProjectID == states[0].ProjectID || other[0].Slug != "srv-b-redis" {
		t.Fatalf("autre hôte : %+v %v", other, err)
	}
	children, err := f.projects.Children(ctx, o, tenant.AllTeams(), hostB.ID)
	if err != nil || len(children) != 1 || children[0].Parent.ID != hostB.ID {
		t.Fatalf("enfants de l'hôte B : %+v %v", children, err)
	}
	if c, err := f.projects.Children(ctx, o, tenant.Visibility{}, hostA.ID); err != nil || len(c) != 0 {
		t.Errorf("visibilité nulle : %+v %v", c, err)
	}
	// Contrôle d'écriture d'un envoi : l'agent de l'hôte seul.
	err = f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		if r, err := project.RefForAgent(ctx, tx, agentA, web.ID, project.RefContainer, "shop/web"); err != nil || r.ID != states[1].RefID {
			t.Errorf("référence du conteneur pour son agent : %+v %v", r, err)
		}
		if _, err := project.RefForAgent(ctx, tx, agentB, web.ID, project.RefContainer, "shop/web"); !errors.Is(err, project.ErrNotFound) {
			t.Errorf("référence du conteneur pour un autre agent : %v", err)
		}
		if _, err := project.SightContainers(ctx, tx, audit.System, uuid.Must(uuid.NewV7()), nil, now, project.DefaultMaxContainersPerHost); !errors.Is(err, project.ErrNoHost) {
			t.Errorf("agent sans hôte : %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Hôte archivé : ses conteneurs ne reçoivent plus d'envoi, et son agent n'en signale
	// plus.
	if err := f.projects.SetArchived(ctx, f.actor, o, hostB.Slug, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sight(t, o, agentB, now, sighting("redis", "redis:7")); !errors.Is(err, project.ErrNoHost) {
		t.Errorf("hôte archivé : %v", err)
	}
	err = f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		_, err := project.RefForAgent(ctx, tx, agentB, other[0].ProjectID, project.RefContainer, "redis")
		return err
	})
	if !errors.Is(err, project.ErrNotFound) {
		t.Errorf("conteneur d'un hôte archivé : %v", err)
	}
	// Les hôtes, créés ici sans inscription, ne sont pas journalisés ; les trois conteneurs
	// le sont.
	if n := countOf(f.actions(t, o), audit.ProjectCreated); n != 3 {
		t.Errorf("%d créations journalisées (trois conteneurs)", n)
	}
}

// TestContainerListsAndTeam : les listes écartent les conteneurs sauf s'ils sont inclus ;
// un conteneur suit l'équipe de son hôte et ne se rattache pas seul.
func TestContainerListsAndTeam(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	general := f.defaultTeam(t, o)
	web, err := f.orgs.CreateTeam(ctx, f.actor, o, "Web")
	if err != nil {
		t.Fatal(err)
	}
	agentID, host := f.hostWithAgent(t, o, "srv", general)
	if _, err := f.projects.Create(ctx, f.actor, o, f.inTeam(t, o, repo("api", "main"))); err != nil {
		t.Fatal(err)
	}
	states, err := f.sight(t, o, agentID, time.Now().UTC(), sighting("shop/web", "nginx"))
	if err != nil {
		t.Fatal(err)
	}
	names := func(fl project.Filter) []string {
		t.Helper()
		page, err := f.projects.List(ctx, o, tenant.AllTeams(), fl, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range page.Items {
			out = append(out, p.Slug)
		}
		return out
	}
	if got := names(project.Filter{}); !slices.Equal(got, []string{"api", "srv"}) {
		t.Errorf("liste par défaut : %v", got)
	}
	if got := names(project.Filter{Containers: true}); !slices.Equal(got, []string{"api", "srv", "srv-shop-web"}) {
		t.Errorf("conteneurs inclus : %v", got)
	}
	if got := names(project.Filter{Kind: project.KindHost, Containers: true}); !slices.Equal(got, []string{"srv", "srv-shop-web"}) {
		t.Errorf("serveurs et conteneurs : %v", got)
	}
	if got := names(project.Filter{Kind: project.KindHost}); !slices.Equal(got, []string{"srv"}) {
		t.Errorf("serveurs : %v", got)
	}
	if err := f.projects.SetTeam(ctx, f.actor, o, states[0].Slug, web.ID); !isKey(err, project.KeyContainerTeam) {
		t.Errorf("rattachement d'un conteneur seul : %v", err)
	}
	if err := f.projects.SetTeam(ctx, f.actor, o, host.Slug, web.ID); err != nil {
		t.Fatal(err)
	}
	child, err := f.projects.Get(ctx, o, tenant.OnlyTeams(web.ID), states[0].Slug)
	if err != nil || child.TeamID != web.ID {
		t.Fatalf("le conteneur suit son hôte : %+v %v", child, err)
	}
	if _, err := f.projects.Get(ctx, o, tenant.OnlyTeams(general), states[0].Slug); !errors.Is(err, project.ErrNotFound) {
		t.Errorf("conteneur visible de l'ancienne équipe : %v", err)
	}
	// Nom, description et étiquettes d'un conteneur se modifient ; sa référence reste.
	if err := f.projects.Update(ctx, f.actor, o, states[0].Slug, project.Input{Name: "Boutique", Labels: project.Labels{"env": "prod"}}, false); err != nil {
		t.Fatal(err)
	}
	if child, _ = f.projects.Get(ctx, o, tenant.AllTeams(), states[0].Slug); child.Name != "Boutique" || len(child.Refs) != 1 {
		t.Errorf("conteneur modifié : %+v", child)
	}
	// La base refuse un conteneur dans une autre équipe que son hôte.
	err = f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `UPDATE projects SET team_id = $2 WHERE id = $1`, states[0].ProjectID, general)
		return err
	})
	if err == nil {
		t.Error("conteneur rattaché à une autre équipe que son hôte")
	}
}

// TestContainerArchiving : un conteneur absent depuis plus de N jours est archivé
// (journalisé), revient s'il redémarre ; archivé par un utilisateur, il reste archivé et
// l'agent l'ignore ; archivé pour absence, il ne se réactive pas à la main.
func TestContainerArchiving(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	agentID, _ := f.hostWithAgent(t, o, "srv", f.defaultTeam(t, o))
	t0 := time.Now().UTC().Round(time.Microsecond)
	states, err := f.sight(t, o, agentID, t0, sighting("web", "nginx"), sighting("db", "postgres"))
	if err != nil {
		t.Fatal(err)
	}
	clock := t0.Add(3 * 24 * time.Hour)
	archiver := project.NewArchiver(f.tdb.App, 7*24*time.Hour, func() time.Time { return clock })
	if n, err := archiver.Archive(ctx, o); err != nil || n != 0 {
		t.Fatalf("après 3 jours : %d %v", n, err)
	}
	// Seul « web » est encore signalé ; « db » a disparu.
	if _, err := f.sight(t, o, agentID, t0.Add(5*24*time.Hour), sighting("web", "nginx")); err != nil {
		t.Fatal(err)
	}
	clock = t0.Add(7*24*time.Hour + time.Hour)
	if n, err := archiver.Archive(ctx, o); err != nil || n != 1 {
		t.Fatalf("après 7 jours : %d %v", n, err)
	}
	if n, err := archiver.Archive(ctx, o); err != nil || n != 0 {
		t.Fatalf("second passage : %d %v", n, err)
	}
	db, _ := f.projects.Get(ctx, o, tenant.AllTeams(), states[0].Slug)
	if db.Container.Key != "db" || db.ArchivedAt == nil || !db.Container.ArchivedAbsent {
		t.Fatalf("conteneur absent : %+v %+v", db, db.Container)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, db.Slug, false); !isKey(err, project.KeyContainerAbsent) {
		t.Errorf("réactivation à la main : %v", err)
	}
	// Il redémarre : son projet revient, avec son historique.
	back, err := f.sight(t, o, agentID, clock, sighting("db", "postgres"))
	if err != nil || !back[0].Reactivated || back[0].Ignored || back[0].ProjectID != db.ID {
		t.Fatalf("retour : %+v %v", back, err)
	}
	if db, _ = f.projects.Get(ctx, o, tenant.AllTeams(), db.Slug); db.ArchivedAt != nil || db.Container.ArchivedAbsent {
		t.Fatalf("conteneur revenu : %+v", db)
	}
	// Archivé par un utilisateur : l'agent l'ignore, il reste archivé ; réactivé à la
	// main, il l'est de nouveau.
	if err := f.projects.SetArchived(ctx, f.actor, o, db.Slug, true); err != nil {
		t.Fatal(err)
	}
	ignored, err := f.sight(t, o, agentID, clock, sighting("db", "postgres"))
	if err != nil || !ignored[0].Ignored || ignored[0].Reactivated {
		t.Fatalf("conteneur archivé à la main : %+v %v", ignored, err)
	}
	if db, _ = f.projects.Get(ctx, o, tenant.AllTeams(), db.Slug); db.ArchivedAt == nil {
		t.Fatal("conteneur archivé à la main réactivé par l'agent")
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, db.Slug, false); err != nil {
		t.Fatal(err)
	}
	actions := f.actions(t, o)
	if countOf(actions, audit.ProjectArchived) != 2 || countOf(actions, audit.ProjectUnarchived) != 2 {
		t.Errorf("journal : %v", actions)
	}
}

// TestArchiverJobs : l'échéance met en file un archivage par organisation active, une
// seule fois ; le job d'une organisation archive ses conteneurs absents ; sans
// organisation, il échoue sans réessai.
func TestArchiverJobs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	archivedOrg := f.org(t, "b")
	if err := f.orgs.SetArchived(ctx, f.actor, archivedOrg, true); err != nil {
		t.Fatal(err)
	}
	agentID, _ := f.hostWithAgent(t, o, "srv", f.defaultTeam(t, o))
	t0 := time.Now().UTC()
	if _, err := f.sight(t, o, agentID, t0, sighting("web", "nginx")); err != nil {
		t.Fatal(err)
	}
	archiver := project.NewArchiver(f.tdb.App, 0, func() time.Time { return t0.Add(project.DefaultArchiveAfter + time.Minute) })
	if sc := archiver.Schedule(); sc.Name != project.ArchiveAllKind || sc.Every != project.ArchiveEvery || sc.Job.Kind != project.ArchiveAllKind {
		t.Fatalf("échéance : %+v", sc)
	}
	for range 2 {
		if err := archiver.AllHandler().Handle(ctx, jobs.Execution{Kind: project.ArchiveAllKind}); err != nil {
			t.Fatal(err)
		}
	}
	var queued []string
	err := f.tdb.App.InTx(ctx, func(tx *db.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT org_id::text FROM jobs WHERE kind = $1 AND status = 'pending'`, project.ArchiveOrgKind)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			queued = append(queued, id)
		}
		return rows.Err()
	})
	if err != nil || len(queued) != 1 || queued[0] != o.String() {
		t.Fatalf("jobs en file : %v %v", queued, err)
	}
	if err := archiver.OrgHandler().Handle(ctx, jobs.Execution{Kind: project.ArchiveOrgKind, OrgID: o}); err != nil {
		t.Fatal(err)
	}
	page, err := f.projects.List(ctx, o, tenant.AllTeams(), project.Filter{Archived: true, Containers: true}, "", 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].Container == nil || !page.Items[0].Container.ArchivedAbsent {
		t.Fatalf("conteneur archivé par le job : %+v %v", page.Items, err)
	}
	if err := archiver.OrgHandler().Handle(ctx, jobs.Execution{Kind: project.ArchiveOrgKind}); err == nil || !jobs.IsPermanent(err) {
		t.Errorf("job sans organisation : %v", err)
	}
}
