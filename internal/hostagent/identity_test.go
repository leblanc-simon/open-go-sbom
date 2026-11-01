package hostagent

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func imageID(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// TestIdentity : l'identité d'un conteneur, en table (décision du 1er novembre 2026).
func TestIdentity(t *testing.T) {
	compose := func(project, service string) map[string]string {
		return map[string]string{LabelComposeProject: project, LabelComposeService: service, "autre": "x"}
	}
	for _, tc := range []struct {
		name    string
		c       Container
		key     string
		compose bool
		ok      bool
	}{
		{"service Compose", Container{Names: []string{"shop-web-1"}, Labels: compose("shop", "web")}, "shop/web", true, true},
		{"réplique du même service", Container{Names: []string{"shop-web-2"}, Labels: compose("shop", "web")}, "shop/web", true, true},
		{"conteneur recréé, autre nom", Container{Names: []string{"shop_web_run_abc"}, Labels: compose("shop", "web")}, "shop/web", true, true},
		{"podman-compose", Container{Names: []string{"shop_db_1"}, Labels: map[string]string{
			LabelPodmanComposeProject: "shop", LabelComposeService: "db"}}, "shop/db", true, true},
		{"sans étiquette : le nom", Container{Names: []string{"redis-cache"}}, "redis-cache", false, true},
		{"projet sans service : le nom", Container{Names: []string{"seul"}, Labels: map[string]string{LabelComposeProject: "shop"}}, "seul", false, true},
		{"étiquette illisible : le nom", Container{Names: []string{"web"}, Labels: compose("shop", "w/eb")}, "web", false, true},
		{"premier nom lisible", Container{Names: []string{"-x", "bon_nom"}}, "bon_nom", false, true},
		{"aucun nom lisible", Container{Names: []string{"", "/x"}}, "", false, false},
		{"rien", Container{}, "", false, false},
	} {
		key, compose, ok := Identity(tc.c)
		if key != tc.key || compose != tc.compose || ok != tc.ok {
			t.Errorf("%s : %q %v %v", tc.name, key, compose, ok)
		}
	}
}

type stubEngine struct{ name string }

func (e stubEngine) Name() string                                                { return e.name }
func (e stubEngine) Socket() string                                              { return "/run/" + e.name + ".sock" }
func (e stubEngine) Containers(context.Context) ([]Container, error)             { return nil, nil }
func (e stubEngine) ExportImage(context.Context, string, io.Writer, int64) error { return nil }

// TestWorkloads : trois services distincts sur deux images donnent trois identités ;
// deux répliques d'un service n'en donnent qu'une, avec l'image du conteneur démarré le
// plus récemment ; un conteneur sans identité ou sans empreinte d'image est écarté.
func TestWorkloads(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	compose := func(svc string) map[string]string {
		return map[string]string{LabelComposeProject: "shop", LabelComposeService: svc}
	}
	docker, podman := stubEngine{"docker"}, stubEngine{"podman"}
	got, skipped := Workloads(map[ContainerEngine][]Container{
		docker: {
			{ID: "1", Names: []string{"shop-web-1"}, Image: "nginx:1.27", ImageID: imageID('a'), Labels: compose("web"), StartedAt: t0},
			{ID: "2", Names: []string{"shop-web-2"}, Image: "nginx:1.28", ImageID: imageID('b'), Labels: compose("web"), StartedAt: t0.Add(time.Hour)},
			{ID: "3", Names: []string{"shop-api-1"}, Image: "nginx:1.27", ImageID: imageID('a'), Labels: compose("api"), StartedAt: t0},
			{ID: "4", Names: []string{"sans-image"}, ImageID: "inconnu"},
			{ID: "5", Names: []string{"/"}, ImageID: imageID('a')},
		},
		podman: {
			{ID: "6", Names: []string{"redis"}, Image: "redis:7", ImageID: imageID('c'), StartedAt: t0},
		},
	})
	if skipped != 2 {
		t.Errorf("%d écartés", skipped)
	}
	keys := make([]string, len(got))
	for i, w := range got {
		keys[i] = w.Key
	}
	if !slices.Equal(keys, []string{"redis", "shop/api", "shop/web"}) {
		t.Fatalf("identités %v", keys)
	}
	web := got[2]
	if web.Replicas != 2 || web.ImageID != imageID('b') || web.Image != "nginx:1.28" || !web.StartedAt.Equal(t0.Add(time.Hour)) ||
		!slices.Equal(web.Names, []string{"shop-web-1", "shop-web-2"}) || web.ComposeProject != "shop" || web.ComposeService != "web" {
		t.Errorf("service web %+v", web)
	}
	if got[0].Engine.Name() != "podman" || got[0].ComposeProject != "" || got[0].Replicas != 1 {
		t.Errorf("redis %+v", got[0])
	}
	// Une identité vue sur deux moteurs : le conteneur le plus récent l'emporte.
	got, _ = Workloads(map[ContainerEngine][]Container{
		docker: {{ID: "1", Names: []string{"web"}, Image: "a", ImageID: imageID('a'), StartedAt: t0}},
		podman: {{ID: "2", Names: []string{"web"}, Image: "b", ImageID: imageID('b'), StartedAt: t0.Add(time.Minute)}},
	})
	if len(got) != 1 || got[0].Engine.Name() != "podman" || got[0].Replicas != 2 || !slices.Equal(got[0].Names, []string{"web"}) {
		t.Errorf("deux moteurs : %+v", got)
	}
	// Plus de seize noms : les seize premiers, triés.
	var many []Container
	for i := range 20 {
		many = append(many, Container{ID: string(rune('a' + i)), Names: []string{"shop-web-" + string(rune('a'+i))},
			ImageID: imageID('a'), Labels: compose("web")})
	}
	got, _ = Workloads(map[ContainerEngine][]Container{docker: many})
	if len(got) != 1 || got[0].Replicas != 20 || len(got[0].Names) != maxReportedNames || got[0].Image != imageID('a') {
		t.Errorf("vingt répliques : %+v", got)
	}
}
