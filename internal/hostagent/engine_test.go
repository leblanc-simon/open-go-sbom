package hostagent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEngine imite l'API Docker d'un moteur sur une socket Unix (httptest) : version,
// conteneurs en cours, inspection, export d'image. Il compte les connexions reçues.
type fakeEngine struct {
	podman     bool
	containers []map[string]any
	started    map[string]string
	images     map[string][]byte
	conns      atomic.Int64
	exports    atomic.Int64
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	write := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.URL.Path == "/version":
		if f.podman {
			write(map[string]any{"Version": "5.2.0", "Components": []map[string]any{{"Name": "Podman Engine", "Version": "5.2.0"}}})
			return
		}
		write(map[string]any{"Version": "29.0.0", "Platform": map[string]any{"Name": "Docker Engine - Community"},
			"Components": []map[string]any{{"Name": "Engine"}, {"Name": "containerd"}}})
	case r.URL.Path == "/containers/json":
		if r.URL.Query().Get("all") != "" {
			http.Error(w, "all inattendu", http.StatusBadRequest)
			return
		}
		write(f.containers)
	case strings.HasPrefix(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
		write(map[string]any{"Id": id, "State": map[string]any{"Running": true, "StartedAt": f.started[id]}})
	case strings.HasPrefix(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/get"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/images/"), "/get")
		data, ok := f.images[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		f.exports.Add(1)
		w.Header().Set("Content-Type", "application/x-tar")
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

// serveEngine sert f sur une socket Unix et renvoie son chemin.
func serveEngine(t *testing.T, f *fakeEngine) string {
	t.Helper()
	// Un chemin court : une socket Unix est bornée à 108 octets.
	dir, err := os.MkdirTemp("", "eng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "engine.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.Listener = l
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			f.conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return path
}

func TestSocketEngine(t *testing.T) {
	ctx := context.Background()
	f := &fakeEngine{
		containers: []map[string]any{
			{"Id": "c1", "Names": []string{"/shop-web-1"}, "Image": "nginx:1.27", "ImageID": imageID('a'), "State": "running",
				"Labels": map[string]string{LabelComposeProject: "shop", LabelComposeService: "web"}},
			{"Id": "c2", "Names": []string{"/redis"}, "Image": "redis:7", "ImageID": strings.Repeat("b", 64), "State": "running"},
			{"Id": "c3", "Names": []string{"/arrete"}, "Image": "x", "ImageID": imageID('c'), "State": "exited"},
		},
		started: map[string]string{"c1": "2026-10-31T08:00:00.123456789Z", "c2": "0001-01-01T00:00:00Z"},
		images:  map[string][]byte{imageID('a'): []byte("archive")},
	}
	e := NewSocketEngine(serveEngine(t, f), 5*time.Second)
	defer e.Close()
	if e.Name() != e.Socket() {
		t.Errorf("nom avant détection %q", e.Name())
	}
	list, err := e.Containers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() != EngineDocker || len(list) != 2 {
		t.Fatalf("%s : %+v", e.Name(), list)
	}
	if c := list[0]; c.ID != "c1" || !slices.Equal(c.Names, []string{"shop-web-1"}) || c.ImageID != imageID('a') ||
		c.Labels[LabelComposeService] != "web" || !c.StartedAt.Equal(time.Date(2026, 10, 31, 8, 0, 0, 123456789, time.UTC)) {
		t.Errorf("conteneur %+v", c)
	}
	if c := list[1]; c.ImageID != imageID('b') || !c.StartedAt.IsZero() {
		t.Errorf("identifiant d'image sans préfixe, date absente : %+v", c)
	}
	var buf bytes.Buffer
	if err := e.ExportImage(ctx, imageID('a'), &buf, 100); err != nil || buf.String() != "archive" {
		t.Errorf("export : %q %v", buf.String(), err)
	}
	if err := e.ExportImage(ctx, imageID('a'), &bytes.Buffer{}, 3); !errors.Is(err, ErrImageTooLarge) {
		t.Errorf("image trop grosse : %v", err)
	}
	if err := e.ExportImage(ctx, imageID('z'), &bytes.Buffer{}, 100); err == nil {
		t.Error("image inconnue exportée")
	}

	p := &fakeEngine{podman: true}
	pe := NewSocketEngine(serveEngine(t, p), 5*time.Second)
	if _, err := pe.Containers(ctx); err != nil || pe.Name() != EnginePodman {
		t.Errorf("podman : %s %v", pe.Name(), err)
	}

	absent := NewSocketEngine(filepath.Join(t.TempDir(), "absente.sock"), time.Second)
	if _, err := absent.Containers(ctx); !errors.Is(err, ErrEngineAbsent) {
		t.Errorf("socket absente : %v", err)
	}
}

// TestEnginesDisabledByDefault : sans containers.enabled, aucun moteur ; avec, les
// sockets configurées ou celles par défaut.
func TestEnginesDisabledByDefault(t *testing.T) {
	if e := Engines(Containers{Sockets: []string{"/run/docker.sock"}}); e != nil {
		t.Errorf("inventaire désactivé : %v", e)
	}
	if e := Engines(Containers{Enabled: true, Timeout: time.Second}); len(e) != len(DefaultSockets) || e[0].Socket() != DefaultSockets[0] {
		t.Errorf("sockets par défaut : %v", e)
	}
	if e := Engines(Containers{Enabled: true, Sockets: []string{"/run/user/1000/podman/podman.sock"}}); len(e) != 1 ||
		e[0].Socket() != "/run/user/1000/podman/podman.sock" {
		t.Errorf("socket configurée : %v", e)
	}
}

// imageArchive construit une image au format docker-archive (docker save) : une couche
// avec os-release et une base apk d'Alpine, sa configuration et son manifeste.
func imageArchive(t *testing.T, packages map[string]string) []byte {
	t.Helper()
	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	var apk strings.Builder
	names := make([]string, 0, len(packages))
	for n := range packages {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		apk.WriteString("P:" + n + "\nV:" + packages[n] + "\nA:x86_64\nL:MIT\no:" + n + "\n\n")
	}
	for _, f := range []struct{ name, body string }{
		{"etc/os-release", "ID=alpine\nVERSION_ID=3.18.0\nPRETTY_NAME=\"Alpine Linux v3.18\"\n"},
		{"lib/apk/db/installed", apk.String()},
	} {
		if err := lw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := lw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	diff := sha256.Sum256(layer.Bytes())
	config, _ := json.Marshal(map[string]any{"architecture": "amd64", "os": "linux",
		"config": map[string]any{}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + hex.EncodeToString(diff[:])}}})
	configSum := sha256.Sum256(config)
	configName := hex.EncodeToString(configSum[:]) + ".json"
	manifest, _ := json.Marshal([]map[string]any{{"Config": configName, "RepoTags": []string{"test/alpine:1"},
		"Layers": []string{"layer.tar"}}})
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, f := range []struct {
		name string
		body []byte
	}{{"layer.tar", layer.Bytes()}, {configName, config}, {"manifest.json", manifest}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// TestSyftImageScanner : une image exportée est inventoriée depuis son archive, sans
// moteur ; son empreinte est stable d'un scan à l'autre.
func TestSyftImageScanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(path, imageArchive(t, map[string]string{"musl": "1.2.4-r0", "busybox": "1.36.1-r0"}), 0o600); err != nil {
		t.Fatal(err)
	}
	s := SyftImageScanner{Parallelism: 1, Version: "test"}
	inv, err := s.ScanImage(context.Background(), path, "test/alpine:1")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Components < 2 || !bytes.Contains(inv.SBOM, []byte(`"pkg:apk/alpine/musl@1.2.4-r0`)) ||
		!bytes.Contains(inv.SBOM, []byte(`"test/alpine:1"`)) {
		t.Fatalf("%d composants : %.400s", inv.Components, inv.SBOM)
	}
	again, err := s.ScanImage(context.Background(), path, "test/alpine:1")
	if err != nil || again.Fingerprint != inv.Fingerprint {
		t.Errorf("empreinte instable : %v", err)
	}
}
