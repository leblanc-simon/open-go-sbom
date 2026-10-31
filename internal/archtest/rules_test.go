package archtest

import (
	"slices"
	"testing"
)

const mod = "example.com/m"

func TestCheck(t *testing.T) {
	cases := []struct {
		name    string
		pkg     string
		imports []string
		wantErr bool
	}{
		{"adaptateur Syft autorisé", "internal/sbom/syft", []string{"github.com/anchore/syft/syft/format"}, false},
		{"agent serveur importe Syft", "internal/hostagent/scan", []string{"github.com/anchore/syft/syft"}, false},
		{"adaptateur Grype autorisé", "internal/vuln/grype", []string{"github.com/anchore/grype/grype"}, false},
		{"Grype dans web", "internal/web", []string{"github.com/anchore/grype/grype"}, true},
		{"Syft dans le modèle sbom", "internal/sbom", []string{"github.com/anchore/syft/syft/sbom"}, true},
		{"Grype dans vuln", "internal/vuln", []string{"github.com/anchore/grype/grype/match"}, true},
		{"Grant hors de son adaptateur", "internal/license", []string{"github.com/anchore/grant/grant"}, true},
		{"préfixe voisin non autorisé", "internal/sbom/syftx", []string{"github.com/anchore/syft/syft"}, true},
		{"bibliothèque voisine du nom", "internal/web", []string{"github.com/anchore/syftlike"}, false},
		{"net/http dans le métier", "internal/inventory", []string{"net/http"}, true},
		{"html/template dans le métier", "internal/search", []string{"html/template"}, true},
		{"net/http dans web", "internal/web", []string{"net/http", "html/template"}, false},
		{"net/http/httptest reste permis", "internal/jobs", []string{"net/http/httptest"}, false},
		{"métier importe web", "internal/project", []string{mod + "/internal/web"}, true},
		{"métier importe render", "internal/dashboard", []string{mod + "/internal/render"}, true},
		{"locale reste sans HTTP", "internal/locale", []string{"net/http"}, true},
		{"agent importe locale", "internal/hostagent", []string{mod + "/internal/locale"}, true},
		{"cmd importe web", "cmd/ogsbom-server", []string{mod + "/internal/web", mod + "/internal/api/gen"}, false},
		{"web importe le métier", "internal/web", []string{mod + "/internal/project"}, false},
		{"agent importe db", "internal/hostagent", []string{mod + "/internal/db"}, true},
		{"client agent importe inventory", "internal/agentclient", []string{mod + "/internal/inventory"}, true},
		{"agent importe sbom", "internal/repoagent", []string{mod + "/internal/sbom"}, false},
		{"forge importe agentclient", "internal/forge", []string{mod + "/internal/agentclient"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Check(mod, []Package{{Path: c.pkg, Imports: c.imports}})
			if (len(got) > 0) != c.wantErr {
				t.Fatalf("violations = %v, attendu en erreur : %v", got, c.wantErr)
			}
		})
	}
}

func TestCheckReportsEveryViolation(t *testing.T) {
	got := Check(mod, []Package{{
		Path:    "internal/inventory",
		Imports: []string{"net/http", "github.com/anchore/syft/syft", mod + "/internal/web"},
	}})
	var imports []string
	for _, v := range got {
		imports = append(imports, v.Import)
	}
	slices.Sort(imports)
	want := []string{"github.com/anchore/syft/syft", "internal/web", "net/http"}
	if !slices.Equal(imports, want) {
		t.Fatalf("imports en faute = %v, attendu %v", imports, want)
	}
}
