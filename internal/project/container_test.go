package project

import (
	"strings"
	"testing"
	"time"
)

func TestValidContainerKey(t *testing.T) {
	for key, want := range map[string]bool{
		"shop/web":                      true,
		"redis-cache":                   true,
		"Shop_1/web.v2":                 true,
		strings.Repeat("a", 255):        true,
		strings.Repeat("a", 256):        false,
		strings.Repeat("a", 129) + "/b": false,
		"a/" + strings.Repeat("b", 128): false,
		"":                              false,
		"/web":                          false,
		"shop/":                         false,
		"a/b/c":                         false,
		"-web":                          false,
		"web cache":                     false,
		"wéb":                           false,
	} {
		if got := ValidContainerKey(key); got != want {
			t.Errorf("%q : %v", key, got)
		}
	}
}

func validContext() ContainerContext {
	started := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	return ContainerContext{Engine: EngineDocker, Names: []string{"shop-web-1"}, Replicas: 1, Image: "nginx:1.27",
		ImageID: "sha256:" + strings.Repeat("a", 64), ComposeProject: "shop", ComposeService: "web", StartedAt: &started}
}

func TestContainerContextValidate(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if err := validContext().Validate(now); err != nil {
		t.Fatalf("contexte valide refusé : %v", err)
	}
	if c := validContext(); c.ShortImageID() != "aaaaaaaaaaaa" {
		t.Errorf("empreinte abrégée %q", c.ShortImageID())
	}
	future, old := now.Add(2*time.Hour), time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, f := range map[string]func(*ContainerContext){
		"moteur":           func(c *ContainerContext) { c.Engine = "containerd" },
		"sans nom":         func(c *ContainerContext) { c.Names = nil },
		"trop de noms":     func(c *ContainerContext) { c.Names = make([]string, 17) },
		"nom":              func(c *ContainerContext) { c.Names = []string{"/web"} },
		"répliques":        func(c *ContainerContext) { c.Replicas = 0 },
		"image vide":       func(c *ContainerContext) { c.Image = "" },
		"image espace":     func(c *ContainerContext) { c.Image = "nginx latest" },
		"image longue":     func(c *ContainerContext) { c.Image = strings.Repeat("a", 256) },
		"empreinte":        func(c *ContainerContext) { c.ImageID = strings.Repeat("a", 64) },
		"service seul":     func(c *ContainerContext) { c.ComposeProject = "" },
		"projet illisible": func(c *ContainerContext) { c.ComposeProject = "a/b" },
		"démarrage futur":  func(c *ContainerContext) { c.StartedAt = &future },
		"démarrage ancien": func(c *ContainerContext) { c.StartedAt = &old },
	} {
		c := validContext()
		f(&c)
		if err := c.Validate(now); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestValidateSightings(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ok := []ContainerSighting{{Key: "shop/web", Context: validContext()}, {Key: "redis", Context: validContext()}}
	if err := ValidateSightings(ok, now); err != nil {
		t.Fatalf("signalement valide refusé : %v", err)
	}
	if err := ValidateSightings(append(ok, ContainerSighting{Key: "redis", Context: validContext()}), now); keyOf(err) != KeyContainerInvalid {
		t.Errorf("identité répétée : %v", err)
	}
	if err := ValidateSightings([]ContainerSighting{{Key: "a b", Context: validContext()}}, now); keyOf(err) != KeyContainerInvalid {
		t.Errorf("identité invalide : %v", err)
	}
	if err := ValidateSightings(make([]ContainerSighting, MaxContainers+1), now); keyOf(err) != KeyContainersTooMany {
		t.Errorf("trop de conteneurs : %v", err)
	}
}

func TestKindCondition(t *testing.T) {
	for _, tc := range []struct {
		kind       Kind
		containers bool
		want       string
	}{
		{"", false, `p.kind <> 'container'`},
		{"", true, ""},
		{KindHost, false, `p.kind = $?`},
		{KindHost, true, `p.kind IN ($?, 'container')`},
	} {
		if got := kindCondition(tc.kind, tc.containers); got != tc.want {
			t.Errorf("%q, %v : %q", tc.kind, tc.containers, got)
		}
	}
}
