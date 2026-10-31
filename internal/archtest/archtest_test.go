package archtest

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepository applique les règles au dépôt lui-même : c'est ce test qui fait
// échouer la CI au premier écart.
func TestRepository(t *testing.T) {
	module, pkgs, err := Load(context.Background(), filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if module != "leblanc.io/open-go-sbom" {
		t.Fatalf("module = %q", module)
	}
	if len(pkgs) == 0 {
		t.Fatal("aucun paquet chargé")
	}
	for _, v := range Check(module, pkgs) {
		t.Error(v)
	}
}

// TestFaultyModule charge un module de test qui importe Grype depuis web, à travers un
// faux module local : le chargeur et les règles doivent ensemble détecter la faute.
func TestFaultyModule(t *testing.T) {
	module, pkgs, err := Load(context.Background(), filepath.Join("testdata", "faulty"))
	if err != nil {
		t.Fatal(err)
	}
	got := Check(module, pkgs)
	if len(got) != 1 {
		t.Fatalf("violations = %v, attendu exactement une", got)
	}
	if got[0].Package != "internal/web" || !strings.HasPrefix(got[0].Import, "github.com/anchore/grype") {
		t.Fatalf("violation inattendue : %v", got[0])
	}
}
