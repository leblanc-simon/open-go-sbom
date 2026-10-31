package schema

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"leblanc.io/open-go-sbom/internal/sbom"
)

var (
	once      sync.Once
	validator *Validator
	newErr    error
)

func get(t *testing.T) *Validator {
	t.Helper()
	once.Do(func() { validator, newErr = New() })
	if newErr != nil {
		t.Fatal(newErr)
	}
	return validator
}

func TestValidateTestdata(t *testing.T) {
	v := get(t)
	cases := map[string]struct {
		format  sbom.Format
		version string
	}{
		"debian-12.cdx15.json":         {sbom.FormatCycloneDX, "1.5"},
		"rhel-8.cdx16.json":            {sbom.FormatCycloneDX, "1.6"},
		"portail-client.cdx16.json":    {sbom.FormatCycloneDX, "1.6"},
		"portail-client-ia.cdx16.json": {sbom.FormatCycloneDX, "1.6"},
		"ubuntu-24.04.cdx17.json":      {sbom.FormatCycloneDX, "1.7"},
		"ubuntu-24.04.spdx23.json":     {sbom.FormatSPDX, "2.3"},
		"rhel-8.spdx23.json":           {sbom.FormatSPDX, "2.3"},
		"alpine-3.20.spdx23.json":      {sbom.FormatSPDX, "2.3"},
		"alpine-3.20.syft.json":        {sbom.FormatSyft, "16.1.11"},
	}
	for name, tc := range cases {
		data, err := os.ReadFile(filepath.Join("../../../testdata/sbom", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Validate(tc.format, tc.version, data); err != nil {
			t.Errorf("%s : %v", name, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	v := get(t)
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"a","hashes":[{"alg":"SHA-256","content":"zz"}]}]}`
	err := v.Validate(sbom.FormatCycloneDX, "1.6", []byte(doc))
	e, ok := sbom.AsError(err)
	if !ok || e.Key != sbom.KeySchemaInvalid || !strings.HasPrefix(e.Detail, "/components/0") {
		t.Fatalf("erreur %v", err)
	}
	if strings.Contains(e.Detail, "zz") {
		t.Errorf("le détail cite le document : %q", e.Detail)
	}
	err = v.Validate(sbom.FormatSPDX, "2.3", []byte(`{"spdxVersion":"SPDX-2.3"}`))
	if e, ok := sbom.AsError(err); !ok || e.Key != sbom.KeySchemaInvalid || e.Detail != "/" {
		t.Errorf("SPDX incomplet : %v", err)
	}
	err = v.Validate(sbom.FormatCycloneDX, "1.4", []byte(`{}`))
	if e, ok := sbom.AsError(err); !ok || e.Key != sbom.KeyUnsupportedFormat {
		t.Errorf("version sans schéma : %v", err)
	}
	err = v.Validate(sbom.FormatCycloneDX, "1.6", []byte(`{`))
	if e, ok := sbom.AsError(err); !ok || e.Key != sbom.KeyMalformed {
		t.Errorf("JSON illisible : %v", err)
	}
	if !v.Supports(sbom.FormatCycloneDX, "1.7") || v.Supports(sbom.FormatSyft, "16") {
		t.Error("Supports")
	}
}

// Un identifiant de licence SPDX récent est accepté à la réception mais refusé par le
// schéma officiel de CycloneDX 1.6.
func TestLicenseEnumeration(t *testing.T) {
	v := get(t)
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"perl","licenses":[{"license":{"id":"Artistic-dist"}}]}]}`)
	if err := v.Validate(sbom.FormatCycloneDX, "1.6", doc); err != nil {
		t.Errorf("réception : %v", err)
	}
	if err := v.ValidateStrict(sbom.FormatCycloneDX, "1.6", doc); err == nil {
		t.Error("le schéma officiel devrait refuser Artistic-dist")
	}
	ids := v.CycloneDXLicenseIDs("1.6")
	if !ids["MIT"] || ids["Artistic-dist"] || v.CycloneDXLicenseIDs("1.4") != nil {
		t.Errorf("identifiants : MIT %v, Artistic-dist %v", ids["MIT"], ids["Artistic-dist"])
	}
}

func TestPointer(t *testing.T) {
	if p := pointer([]string{"a/b", "c~d", "0"}); p != "/a~1b/c~0d/0" {
		t.Errorf("pointeur %q", p)
	}
	if p := pointer([]string{strings.Repeat("x", 300)}); len(p) != maxPointer {
		t.Errorf("pointeur non borné : %d", len(p))
	}
	if _, err := (noNetwork{}).Load("http://example.com"); err == nil {
		t.Error("le chargeur doit refuser le réseau")
	}
}
