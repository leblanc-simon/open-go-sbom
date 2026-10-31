package benchdata

import (
	"bytes"
	"testing"

	"leblanc.io/open-go-sbom/internal/sbom"
	"leblanc.io/open-go-sbom/internal/sbom/schema"
)

func TestSyntheticCycloneDX(t *testing.T) {
	a, err := SyntheticCycloneDX(5000, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SyntheticCycloneDX(5000, 2)
	if bytes.Equal(a, b) {
		t.Fatal("deux variantes identiques")
	}
	h, err := sbom.Precheck(bytes.NewReader(a), sbom.Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxComponents: 50_000})
	if err != nil || h.Format != sbom.FormatCycloneDX || h.Components != 5000 {
		t.Fatalf("en-tête %+v, %v", h, err)
	}
	v, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(h.Format, h.SpecVersion, a); err != nil {
		t.Fatalf("SBOM non conforme : %v", err)
	}
	if small, _ := SyntheticCycloneDX(3, 0); bytes.Count(small, []byte(`"purl"`)) != 3 {
		t.Fatal("borne n")
	}
}
