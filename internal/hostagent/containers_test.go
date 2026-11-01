package hostagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agentclient/gen"
)

// fakeImages remplace Syft : l'inventaire d'une image dépend de son archive seule, et le
// SBOM porte l'empreinte d'inventaire, que le faux serveur range.
type fakeImages struct {
	mu    sync.Mutex
	scans map[string]int // par contenu d'archive
	err   error
}

func (f *fakeImages) ScanImage(_ context.Context, archive, _ string) (Inventory, error) {
	data, err := os.ReadFile(archive)
	if err != nil {
		return Inventory{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scans == nil {
		f.scans = map[string]int{}
	}
	f.scans[string(data)]++
	if f.err != nil {
		return Inventory{}, f.err
	}
	fp := sha256.Sum256(data)
	return Inventory{SBOM: []byte(hex.EncodeToString(fp[:])), Fingerprint: fp, Components: 2, Started: time.Now().UTC()}, nil
}

func (f *fakeImages) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.scans {
		n += v
	}
	return n
}

// containerHarness : un agent dont l'inventaire des conteneurs est activé sur un faux
// moteur Docker (socket Unix).
func containerHarness(t *testing.T, engine *fakeEngine) (*harness, *fakeImages) {
	t.Helper()
	socket := serveEngine(t, engine)
	h := newHarness(t, func(c *Config) {
		c.Containers = Containers{Enabled: true, Sockets: []string{socket}, MaxImageMiB: 16, Timeout: 5 * time.Second}
	})
	images := &fakeImages{}
	h.agent.o.Engines, h.agent.o.ImageScanner = Engines(h.agent.o.Config.Containers), images
	return h, images
}

func composeContainer(id, name, service string, image byte) map[string]any {
	return map[string]any{"Id": id, "Names": []string{"/" + name}, "Image": "img-" + string(image), "ImageID": imageID(image),
		"State": "running", "Labels": map[string]string{LabelComposeProject: "shop", LabelComposeService: service}}
}

// TestContainersCycle : trois conteneurs de services distincts sur deux images donnent
// trois projets enfants et deux scans d'image ; deux répliques d'un même service, un
// seul projet. Au cycle suivant, les inventaires connus sont confirmés sans scan ; un
// projet archivé par un utilisateur n'est plus inventorié.
func TestContainersCycle(t *testing.T) {
	ctx := context.Background()
	engine := &fakeEngine{
		containers: []map[string]any{
			composeContainer("c1", "shop-web-1", "web", 'a'),
			composeContainer("c2", "shop-web-2", "web", 'a'),
			composeContainer("c3", "shop-api-1", "api", 'a'),
			{"Id": "c4", "Names": []string{"/redis"}, "Image": "redis:7", "ImageID": imageID('b'), "State": "running"},
		},
		started: map[string]string{"c1": "2026-10-31T08:00:00Z", "c2": "2026-10-31T09:00:00Z"},
		images:  map[string][]byte{imageID('a'): []byte("image a"), imageID('b'): []byte("image b")},
	}
	h, images := containerHarness(t, engine)
	res, err := h.agent.Cycle(ctx)
	if err != nil || res.Outcome != OutcomeSent || res.Containers == nil {
		t.Fatalf("premier cycle : %+v %v", res, err)
	}
	if c := *res.Containers; c.Workloads != 3 || c.Images != 2 || c.Sent != 3 || c.Failed != 0 {
		t.Fatalf("conteneurs : %+v", c)
	}
	if images.total() != 2 || engine.exports.Load() != 2 {
		t.Fatalf("%d scans, %d exports : une image partagée n'est scannée qu'une fois", images.total(), engine.exports.Load())
	}
	if len(h.srv.children) != 3 || h.srv.childUploads["shop/web"] != 1 || h.srv.childUploads["shop/api"] != 1 || h.srv.childUploads["redis"] != 1 {
		t.Fatalf("projets enfants %v, envois %v", h.srv.children, h.srv.childUploads)
	}
	rep := h.srv.reports[0]
	var web gen.ContainerSighting
	for _, c := range rep.Containers {
		if c.Key == "shop/web" {
			web = c
		}
	}
	if rep.Version != "1.2.3" || web.Replicas != 2 || !slices.Equal(web.Names, []string{"shop-web-1", "shop-web-2"}) ||
		web.Engine != gen.Docker || *web.ComposeProject != "shop" || *web.ComposeService != "web" || web.Inventory != nil ||
		web.StartedAt == nil || !web.StartedAt.Equal(time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("signalement du service web : %+v", web)
	}
	// Aucune archive d'image ne reste sur le disque.
	if left, _ := filepath.Glob(filepath.Join(h.agent.o.Config.ImagesDir(), "*")); len(left) != 0 {
		t.Errorf("archives restées : %v", left)
	}
	if info, err := os.Stat(h.agent.o.Config.ImagesDir()); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("répertoire des images : %v %v", info, err)
	}

	// Second cycle : les inventaires connus sont confirmés, sans export ni scan.
	h.srv.ignored = map[string]bool{"redis": true}
	res, err = h.agent.Cycle(ctx)
	if err != nil || res.Containers == nil {
		t.Fatalf("second cycle : %+v %v", res, err)
	}
	if c := *res.Containers; c.Confirmed != 2 || c.Ignored != 1 || c.Sent != 0 || c.Images != 0 {
		t.Fatalf("second cycle : %+v", c)
	}
	if images.total() != 2 || engine.exports.Load() != 2 {
		t.Fatalf("%d scans au second cycle", images.total())
	}
	if inv := h.srv.reports[1].Containers[0].Inventory; inv == nil || inv.Fingerprint != h.srv.childCurrent["redis"] {
		t.Errorf("compte rendu d'inventaire : %+v", inv)
	}

	// Le serveur ne connaît plus l'inventaire du service api : l'image est rescannée et
	// le SBOM renvoyé ; une autre version de l'agent ne se fie pas aux inventaires gardés.
	h.srv.childCurrent["shop/api"] = "autre"
	if res, _ = h.agent.Cycle(ctx); res.Containers.Sent != 1 || res.Containers.Confirmed != 1 || h.srv.childUploads["shop/api"] != 2 {
		t.Fatalf("inventaire réclamé : %+v", res.Containers)
	}
	h.agent.o.Version = "1.2.4"
	if res, _ = h.agent.Cycle(ctx); res.Containers.Sent != 2 || h.srv.reports[3].Containers[1].Inventory != nil {
		t.Fatalf("nouvelle version : %+v", res.Containers)
	}
}

// TestContainersFailures : un scan d'image en échec n'empêche ni les autres conteneurs ni
// le cycle de l'hôte ; un serveur qui refuse le signalement non plus.
func TestContainersFailures(t *testing.T) {
	ctx := context.Background()
	engine := &fakeEngine{
		containers: []map[string]any{
			{"Id": "c1", "Names": []string{"/web"}, "Image": "web", "ImageID": imageID('a'), "State": "running"},
			{"Id": "c2", "Names": []string{"/trop-grosse"}, "Image": "big", "ImageID": imageID('c'), "State": "running"},
		},
		images: map[string][]byte{imageID('a'): []byte("image a"), imageID('c'): make([]byte, 17<<20)},
	}
	h, images := containerHarness(t, engine)
	res, err := h.agent.Cycle(ctx)
	if err != nil || res.Outcome != OutcomeSent {
		t.Fatalf("cycle : %+v %v", res, err)
	}
	if c := *res.Containers; c.Sent != 1 || c.Failed != 1 || images.total() != 1 {
		t.Fatalf("image trop grosse : %+v", c)
	}
	images.err = errors.New("archive illisible")
	h.srv.childCurrent["web"] = "autre"
	if res, err = h.agent.Cycle(ctx); err != nil || res.Containers.Failed != 2 || res.Containers.Sent != 0 {
		t.Fatalf("scan en échec : %+v %v", res.Containers, err)
	}
}

// TestNoSocketWithoutOption : sans containers.enabled, l'agent n'ouvre aucune socket de
// moteur, même configurée ; avec, il l'interroge.
func TestNoSocketWithoutOption(t *testing.T) {
	engine := &fakeEngine{}
	socket := serveEngine(t, engine)
	h := newHarness(t, func(c *Config) { c.Containers.Sockets = []string{socket} })
	h.agent.o.Engines = Engines(h.agent.o.Config.Containers)
	res, err := h.agent.Cycle(context.Background())
	if err != nil || res.Containers != nil || engine.conns.Load() != 0 || len(h.srv.reports) != 0 {
		t.Fatalf("inventaire désactivé : %+v %v, %d connexions", res, err, engine.conns.Load())
	}
	h.agent.o.Config.Containers.Enabled = true
	h.agent.o.Engines, h.agent.o.ImageScanner = Engines(h.agent.o.Config.Containers), &fakeImages{}
	if res, err = h.agent.Cycle(context.Background()); err != nil || res.Containers == nil || engine.conns.Load() == 0 {
		t.Fatalf("inventaire activé : %+v %v, %d connexions", res, err, engine.conns.Load())
	}
	// Une socket par défaut absente est ignorée sans erreur.
	h.agent.o.Config.Containers.Sockets = nil
	h.agent.o.Engines = []ContainerEngine{NewSocketEngine(filepath.Join(t.TempDir(), "absente.sock"), time.Second)}
	if res, err = h.agent.Cycle(context.Background()); err != nil || res.Containers.Workloads != 0 || res.Containers.Failed != 0 {
		t.Fatalf("socket absente : %+v %v", res.Containers, err)
	}
}
