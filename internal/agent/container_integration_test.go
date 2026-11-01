//go:build integration

package agent_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/sbom/syft"
	"leblanc.io/lotor/internal/tenant"
)

func containerReport(key, image string, inv *agent.ContainerInventory) agent.ContainerReport {
	c := project.ContainerContext{Engine: project.EnginePodman, Names: []string{strings.ReplaceAll(key, "/", "-") + "-1"},
		Replicas: 1, Image: image, ImageID: "sha256:" + strings.Repeat("b", 64)}
	if p, s, ok := strings.Cut(key, "/"); ok {
		c.ComposeProject, c.ComposeService = p, s
	}
	return agent.ContainerReport{ContainerSighting: project.ContainerSighting{Key: key, Context: c}, Inventory: inv}
}

// TestReportContainers : le signalement crée les projets enfants sous l'hôte de l'agent
// (journalisé à son nom) ; un SBOM rangé sur la référence d'un conteneur est ensuite
// confirmé par son empreinte, sans renvoi. Un autre agent ne peut rien envoyer au
// conteneur d'un hôte qui n'est pas le sien.
func TestReportContainers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, e := f.hostAgent(t, o, "srv-c", nil)
	other, _ := f.hostAgent(t, o, "srv-d", nil)

	res, err := f.agents.ReportContainers(ctx, p, "1.1.0", []agent.ContainerReport{
		containerReport("shop/web", "nginx:1.27", nil), containerReport("redis", "redis:7", nil)}, "192.0.2.7", "req-c")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].Key != "redis" || !res[0].Created || res[0].Inventory != "" || res[1].Slug != "srv-c-shop-web" {
		t.Fatalf("signalement : %+v", res)
	}
	web, err := f.projects.Get(ctx, o, tenant.AllTeams(), res[1].Slug)
	if err != nil || web.Parent == nil || web.Parent.ID != e.Project.ID || web.TeamID != e.Project.TeamID ||
		web.Container.Context.Engine != project.EnginePodman || web.Container.Context.ComposeService != "web" {
		t.Fatalf("projet enfant : %+v %v", web, err)
	}
	a, _ := f.agents.Get(ctx, o, tenant.AllTeams(), e.Agent.ID)
	if a.Version != "1.1.0" || a.LastSeenAt == nil || !a.LastSeenAt.Equal(f.clock.Now()) {
		t.Errorf("signal de vie : %+v", a)
	}
	created := 0
	for _, x := range f.actions(t, o) {
		if x.Action == audit.ProjectCreated && x.Details["kind"] == "container" {
			created++
			if !strings.HasPrefix(x.ActorEmail, "lotor_agt_") || x.IP != "192.0.2.7" || x.Details["host"] != "srv-c" {
				t.Errorf("journal d'une création : %+v", x)
			}
		}
	}
	if created != 2 {
		t.Errorf("%d créations journalisées", created)
	}

	// Un SBOM rangé sur la référence du conteneur, puis confirmé par son empreinte.
	data, err := os.ReadFile("../../testdata/sbom/alpine-3.20.syft.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := syft.Decode(sbom.FormatSyft, data)
	if err != nil {
		t.Fatal(err)
	}
	fp := sbom.Fingerprint(doc.Components)
	v, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	ing, err := ingest.NewService(ingest.Options{Pool: f.tdb.App, Validator: v, Logger: slog.New(slog.DiscardHandler),
		Limits: ingest.Limits{MaxUpload: 8 << 20, SBOM: sbom.Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxComponents: 20_000}}})
	if err != nil {
		t.Fatal(err)
	}
	ic := ingest.Context{ProjectID: web.ID, RefKind: project.RefContainer, RefName: "shop/web", AgentVersion: "1",
		ScannedAt: f.clock.Now().Add(-time.Hour)}
	if err := ing.Authorize(ctx, o, other.AgentID, ic); !errors.Is(err, ingest.ErrRefUnknown) {
		t.Fatalf("envoi d'un autre agent : %v", err)
	}
	if _, err := f.agents.ReportContainers(ctx, other, "1", []agent.ContainerReport{containerReport("shop/web", "x", nil)}, "", ""); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.projects.Get(ctx, o, tenant.AllTeams(), res[1].Slug); c.Container.Context.Image != "nginx:1.27" {
		t.Errorf("un autre agent a touché ce conteneur : %+v", c.Container)
	}
	commit := ic
	commit.Commit = strings.Repeat("a", 40)
	if err := ing.Authorize(ctx, o, e.Agent.ID, commit); err == nil {
		t.Error("commit accepté pour un conteneur")
	}
	in, err := ing.Receive(ctx, o, e.Agent.ID, ic, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := ing.Decode(ctx, o, in.ID); err != nil {
		t.Fatal(err)
	}
	inv := &agent.ContainerInventory{Fingerprint: fp, ScannedAt: f.clock.Now()}
	res, err = f.agents.ReportContainers(ctx, p, "1.1.0", []agent.ContainerReport{containerReport("shop/web", "nginx:1.27", inv),
		containerReport("redis", "redis:7", inv)}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Inventory != agent.InventoryOutdated || res[1].Inventory != agent.InventoryCurrent {
		t.Fatalf("comptes rendus : %+v", res)
	}
	// Archivé par un utilisateur : ignoré, jamais « current ».
	if err := f.projects.SetArchived(ctx, f.actor, o, res[1].Slug, true); err != nil {
		t.Fatal(err)
	}
	res, err = f.agents.ReportContainers(ctx, p, "1.1.0", []agent.ContainerReport{containerReport("shop/web", "nginx:1.27", inv)}, "", "")
	if err != nil || !res[0].Ignored || res[0].Inventory != "" {
		t.Fatalf("conteneur archivé : %+v %v", res, err)
	}
}

// TestReportContainersRefusals : seul un agent serveur signale des conteneurs, des
// identités valides et distinctes, des contextes bornés ; un hôte archivé n'a plus
// d'enfant.
func TestReportContainersRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, e := f.hostAgent(t, o, "srv-r", nil)
	_, tok, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := f.agents.Authenticate(ctx, tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.agents.ReportContainers(ctx, repo, "1", nil, "", ""); !isKey(err, agent.KeyContainersNotHost) {
		t.Errorf("agent dépôt : %v", err)
	}
	future := f.clock.Now().Add(2 * time.Hour)
	bad := map[string][]agent.ContainerReport{
		"identité":         {containerReport("a b", "x", nil)},
		"identité répétée": {containerReport("web", "x", nil), containerReport("web", "y", nil)},
		"image": {func() agent.ContainerReport {
			r := containerReport("web", "x", nil)
			r.Context.ImageID = "abc"
			return r
		}()},
		"moteur": {func() agent.ContainerReport {
			r := containerReport("web", "x", nil)
			r.Context.Engine = "lxc"
			return r
		}()},
		"démarrage": {func() agent.ContainerReport {
			r := containerReport("web", "x", nil)
			r.Context.StartedAt = &future
			return r
		}()},
		"compose": {func() agent.ContainerReport {
			r := containerReport("web", "x", nil)
			r.Context.ComposeProject = "shop"
			return r
		}()},
		"inventaire": {containerReport("web", "x", &agent.ContainerInventory{ScannedAt: future})},
	}
	for name, reports := range bad {
		if _, err := f.agents.ReportContainers(ctx, p, "1", reports, "", ""); !isKey(err, project.KeyContainerInvalid) {
			t.Errorf("%s : %v", name, err)
		}
	}
	many := make([]agent.ContainerReport, project.MaxContainers+1)
	for i := range many {
		many[i] = containerReport("c"+strings.Repeat("x", i%50)+string(rune('a'+i%26))+string(rune('a'+i/26%26)), "x", nil)
	}
	if _, err := f.agents.ReportContainers(ctx, p, "1", many, "", ""); !isKey(err, project.KeyContainersTooMany) {
		t.Errorf("trop de conteneurs : %v", err)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, e.Project.Slug, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agents.ReportContainers(ctx, p, "1", []agent.ContainerReport{containerReport("web", "x", nil)}, "", ""); authKey(err) != agent.KeyNoHostProject {
		t.Errorf("hôte archivé : %v", err)
	}
}

// TestContainerChildrenBoundedPerHost : SEC2-05. Les projets enfants d'un hôte, actifs ou
// archivés, sont bornés (containers.max_per_host) : un signalement qui créerait davantage
// est refusé en entier, sans projet ni ligne d'audit ; les conteneurs connus se signalent
// toujours, et une identité déjà suivie ne compte pas comme une création.
func TestContainerChildrenBoundedPerHost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	p, e := f.hostAgent(t, o, "srv-c", nil)
	agents := agent.NewService(f.tdb.App, agent.WithClock(f.clock.Now), agent.WithMaxContainersPerHost(5))
	report := func(keys ...string) error {
		reps := make([]agent.ContainerReport, len(keys))
		for i, k := range keys {
			reps[i] = containerReport(k, "nginx:1.27", nil)
		}
		_, err := agents.ReportContainers(ctx, p, "1.1.0", reps, "192.0.2.7", "req")
		return err
	}
	if err := report("c1", "c2", "c3", "c4"); err != nil {
		t.Fatal(err)
	}
	// Archivé par un utilisateur : il compte toujours.
	if err := f.projects.SetArchived(ctx, f.actor, o, "srv-c-c4", true); err != nil {
		t.Fatal(err)
	}
	if err := report("c1", "c5", "c6"); authKey(err) != agent.KeyContainersLimit {
		t.Fatalf("6 projets enfants pour une borne de 5 : %v", err)
	}
	host, err := f.projects.Get(ctx, o, tenant.AllTeams(), e.Project.Slug)
	if err != nil {
		t.Fatal(err)
	}
	children := func() (n, audits int) {
		t.Helper()
		if err := f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM projects WHERE parent_id = $1`, host.ID).Scan(&n); err != nil {
				return err
			}
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = 'project.created' AND details->>'kind' = 'container'`).Scan(&audits)
		}, db.ReadOnly()); err != nil {
			t.Fatal(err)
		}
		return n, audits
	}
	if n, audits := children(); n != 4 || audits != 4 {
		t.Fatalf("après le refus : %d projets enfants, %d créations journalisées", n, audits)
	}
	// Connus plus un nouveau : tient sous la borne.
	if err := report("c1", "c2", "c3", "c4", "c5"); err != nil {
		t.Fatalf("signalement sous la borne : %v", err)
	}
	if err := report("c1", "c2", "c3", "c4", "c5"); err != nil {
		t.Fatalf("signalement des conteneurs connus, à la borne : %v", err)
	}
	if n, _ := children(); n != 5 {
		t.Fatalf("projets enfants : %d", n)
	}
}
