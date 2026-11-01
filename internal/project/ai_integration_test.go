//go:build integration

package project_test

import (
	"context"
	"errors"
	"testing"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// TestAIModeSettings : IA désactivée par défaut ; réglage journalisé à chaque changement ;
// fournisseur externe refusé quand l'instance l'interdit ; réservé aux dépôts actifs ; la
// référence d'un projet n'est visible qu'à l'agent qui le sert.
func TestAIModeSettings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o, other := f.org(t, "a"), f.org(t, "b")
	p, err := f.projects.Create(ctx, f.actor, o, f.inTeam(t, o, repo("api", "main")))
	if err != nil {
		t.Fatal(err)
	}
	if p.AIMode != project.AIDisabled {
		t.Fatalf("réglage par défaut : %q", p.AIMode)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, o, p.Slug, project.AIExternal, false); !isKey(err, project.KeyAIExternalOff) {
		t.Fatalf("fournisseur externe interdit : %v", err)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, o, p.Slug, "magic", true); !isKey(err, project.KeyAIModeInvalid) {
		t.Fatalf("réglage inconnu : %v", err)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, o, p.Slug, project.AIExternal, true); err != nil {
		t.Fatal(err)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, o, p.Slug, project.AIExternal, true); err != nil {
		t.Fatal(err)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, o, p.Slug, project.AILocal, false); err != nil {
		t.Fatal(err)
	}
	got, _ := f.projects.Get(ctx, o, tenant.AllTeams(), p.Slug)
	if got.AIMode != project.AILocal {
		t.Fatalf("réglage relu : %q", got.AIMode)
	}
	if n := countOf(f.actions(t, o), audit.ProjectAIModeChanged); n != 2 {
		t.Fatalf("%d changements journalisés, 2 attendus", n)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, other, p.Slug, project.AILocal, true); !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("autre organisation : %v", err)
	}
	h, err := f.projects.Create(ctx, f.actor, o, f.inTeam(t, o, project.Input{Kind: project.KindHost, Name: "srv", HostRef: "srv"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, o, h.Slug, project.AILocal, true); !isKey(err, project.KeyAIModeInvalid) {
		t.Fatalf("serveur : %v", err)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, p.Slug, true); err != nil {
		t.Fatal(err)
	}
	if err := f.projects.SetAIMode(ctx, f.actor, o, p.Slug, project.AIDisabled, true); !isKey(err, project.KeyProjectArchived) {
		t.Fatalf("projet archivé : %v", err)
	}
}

func TestRefOfAgent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, err := f.projects.Create(ctx, f.actor, o, f.inTeam(t, o, repo("api", "main")))
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci-2", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.projects.AssignAgent(ctx, f.actor, o, p.Slug, &a.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.projects.Get(ctx, o, tenant.AllTeams(), p.Slug)
	ref := got.Refs[0].ID
	err = f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		if id, err := project.RefOfAgent(ctx, tx, a.ID, ref); err != nil || id != p.ID {
			t.Errorf("agent du projet : %v %v", id, err)
		}
		if _, err := project.RefOfAgent(ctx, tx, b.ID, ref); !errors.Is(err, project.ErrNotFound) {
			t.Errorf("autre agent : %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAIModeEffective(t *testing.T) {
	for _, c := range []struct {
		m       project.AIMode
		allowed bool
		want    project.AIMode
	}{
		{project.AIExternal, true, project.AIExternal}, {project.AIExternal, false, project.AILocal},
		{project.AILocal, false, project.AILocal}, {project.AIDisabled, true, project.AIDisabled}, {"x", true, project.AIDisabled},
	} {
		if got := c.m.Effective(c.allowed); got != c.want {
			t.Errorf("%q/%v : %q", c.m, c.allowed, got)
		}
	}
}
