//go:build measure

package hostagent

// Essai sur un vrai moteur de conteneurs, hors CI (étiquette measure) :
//
//	LOTOR_TEST_ENGINE_SOCKET=/run/docker.sock go test -tags measure -count=1 -v \
//	    -run TestRealEngine ./internal/hostagent/
//
// Le moteur (Docker, ou Podman par sa socket) doit faire tourner au moins un conteneur
// dont l'image porte une base de paquets (alpine, debian…). L'essai liste les conteneurs,
// les regroupe par identité, exporte chaque image une fois et la scanne avec Syft, puis
// journalise identités, images, composants et durées.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRealEngine(t *testing.T) {
	socket := os.Getenv("LOTOR_TEST_ENGINE_SOCKET")
	if socket == "" {
		t.Skip("LOTOR_TEST_ENGINE_SOCKET : socket d'un moteur Docker ou Podman")
	}
	ctx := context.Background()
	e := NewSocketEngine(socket, 30*time.Second)
	defer e.Close()
	list, err := e.Containers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	workloads, skipped := Workloads(map[ContainerEngine][]Container{e: list})
	t.Logf("moteur %s : %d conteneurs, %d identités, %d écartés", e.Name(), len(list), len(workloads), skipped)
	if len(workloads) == 0 {
		t.Fatal("aucun conteneur en cours")
	}
	scanner := SyftImageScanner{Parallelism: 2, Version: "essai"}
	scanned := map[string]Inventory{}
	for _, w := range workloads {
		t.Logf("identité %q : %d réplique(s) %v, image %s (%s), compose %q/%q, démarré %s", w.Key, w.Replicas, w.Names, w.Image,
			w.ImageID, w.ComposeProject, w.ComposeService, w.StartedAt.Format(time.RFC3339))
		if _, ok := scanned[w.ImageID]; ok {
			continue
		}
		path := filepath.Join(t.TempDir(), "image.tar")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := e.ExportImage(ctx, w.ImageID, f, 4<<30); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		info, _ := os.Stat(path)
		exported := time.Since(start)
		inv, err := scanner.ScanImage(ctx, path, w.Image)
		if err != nil {
			t.Fatal(err)
		}
		scanned[w.ImageID] = inv
		t.Logf("image %s : archive %d octets exportée en %s, %d composants en %s, SBOM %d octets", w.Image, info.Size(),
			exported.Round(time.Millisecond), inv.Components, inv.Duration.Round(time.Millisecond), len(inv.SBOM))
	}
}
