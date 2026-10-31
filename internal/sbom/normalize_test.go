package sbom

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeComponent(t *testing.T) {
	doc := Normalize(RawDocument{Format: FormatCycloneDX, SpecVersion: "1.6", Components: []RawComponent{{
		PURL: "pkg:NPM/jquery@3.4.1", Name: " jquery ", Version: "3.4.1",
		CPEs:     []string{"cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*", "pas une cpe", "cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*"},
		Licenses: []string{"MIT", " MIT", "", "Apache-2.0"},
		Hashes: []RawHash{{"SHA-256", "0925E8AD7BD971391A8B1E98BE8E87A6971919EB5B60C196485941C3C1DF089A"},
			{"SHA-256", "trop court"}, {"CRC32", "abcd"}},
		Origin: "ia", Confidence: "0.8200001", Model: "example-model",
		Evidence: json.RawMessage(`{ "occurrences": [ {"location": "a.js"} ], "identity": {"field": "name"} }`),
		Scope:    "Required",
	}}})
	if len(doc.Components) != 1 || doc.Skipped != 0 {
		t.Fatalf("composants %d, écartés %d", len(doc.Components), doc.Skipped)
	}
	c := doc.Components[0]
	want := Component{
		PURL: "pkg:npm/jquery@3.4.1", PURLBase: "pkg:npm/jquery", Type: "npm", Name: "jquery", Version: "3.4.1",
		CPEs:     []string{"cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*"},
		Licenses: []string{"Apache-2.0", "MIT"},
		Hashes:   []string{"sha256:0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a"},
		Origin:   OriginIA, Model: "example-model", Scope: ScopeRequired,
		Evidence: json.RawMessage(`{"identity":{"field":"name"},"occurrences":[{"location":"a.js"}]}`),
	}
	if c.Confidence == nil || *c.Confidence != 0.82 {
		t.Errorf("confiance %v", c.Confidence)
	}
	c.Confidence = nil
	if !equalComponents(c, want) {
		t.Errorf("composant\n%+v\nattendu\n%+v", c, want)
	}
}

func equalComponents(a, b Component) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func TestNormalizeWeakIdentification(t *testing.T) {
	doc := Normalize(RawDocument{Components: []RawComponent{
		{Name: "libfoo-interne", Version: "1.2"},
		{PURL: "illisible", Name: "autre", Version: "3"},
		{Version: "1.0"}, // ni nom ni purl : écarté
	}})
	if doc.Skipped != 1 || len(doc.Components) != 2 {
		t.Fatalf("écartés %d, composants %+v", doc.Skipped, doc.Components)
	}
	for _, c := range doc.Components {
		if !c.WeakID || c.Type != "generic" || c.Origin != OriginSyft {
			t.Errorf("composant faible attendu : %+v", c)
		}
	}
	if doc.Components[0].PURL != "pkg:generic/autre@3" || doc.Components[1].PURL != "pkg:generic/libfoo-interne@1.2" {
		t.Errorf("ordre ou purl : %s, %s", doc.Components[0].PURL, doc.Components[1].PURL)
	}
}

func TestNormalizeNameFromPURL(t *testing.T) {
	doc := Normalize(RawDocument{Components: []RawComponent{{PURL: "pkg:pypi/pyyaml@6.0.1"}}})
	c := doc.Components[0]
	if c.Name != "pyyaml" || c.Version != "6.0.1" {
		t.Errorf("nom et version repris du purl : %+v", c)
	}
}

func TestNormalizeBounds(t *testing.T) {
	long := strings.Repeat("x", MaxNameLen+1)
	var cpes []string
	for i := range MaxCPEs + 5 {
		cpes = append(cpes, "cpe:2.3:a:v:p"+strings.Repeat("0", i)+":1:*:*:*:*:*:*:*")
	}
	doc := Normalize(RawDocument{Components: []RawComponent{
		{PURL: "pkg:npm/a@1", Name: long},
		{PURL: "pkg:npm/b@1", Version: strings.Repeat("1", MaxVersionLen+1)},
		{PURL: "pkg:npm/c@1", CPEs: cpes, Model: strings.Repeat("m", MaxModelLen+1),
			Evidence: json.RawMessage(`"` + strings.Repeat("e", MaxEvidenceLen) + `"`), Confidence: "1.5"},
		{PURL: "pkg:npm/d@1", Name: "d\x00", Evidence: json.RawMessage(`{"a":`), Confidence: "NaN", Scope: "autre"},
	}})
	if doc.Skipped != 2 || len(doc.Components) != 2 {
		t.Fatalf("écartés %d, composants %d", doc.Skipped, len(doc.Components))
	}
	c := doc.Components[0]
	if len(c.CPEs) != MaxCPEs || c.Model != "" || c.Evidence != nil || c.Confidence != nil {
		t.Errorf("bornes non appliquées : %d CPE, modèle %q, preuve %d, confiance %v", len(c.CPEs), c.Model, len(c.Evidence), c.Confidence)
	}
	d := doc.Components[1]
	if d.Name != "d" || d.Evidence != nil || d.Confidence != nil || d.Scope != "" {
		t.Errorf("valeurs invalides conservées : %+v", d)
	}
}

func TestNormalizeMergesDuplicates(t *testing.T) {
	a := RawComponent{PURL: "pkg:npm/lodash@4.17.21", Name: "lodash", Licenses: []string{"MIT"},
		CPEs: []string{"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"}, Scope: "optional"}
	b := RawComponent{PURL: "pkg:NPM/lodash@4.17.21", Name: "lodash", Origin: "ia", Confidence: "0.9",
		Licenses: []string{"CC0-1.0"}, Scope: "required", Hashes: []RawHash{{"sha1", strings.Repeat("a", 40)}}}
	one := Normalize(RawDocument{Components: []RawComponent{a, b}})
	two := Normalize(RawDocument{Components: []RawComponent{b, a}})
	if len(one.Components) != 1 || !equalComponents(one.Components[0], two.Components[0]) {
		t.Fatalf("fusion dépendante de l'ordre :\n%+v\n%+v", one.Components, two.Components)
	}
	c := one.Components[0]
	if c.Origin != OriginSyft || c.Scope != ScopeRequired || !slices.Equal(c.Licenses, []string{"CC0-1.0", "MIT"}) ||
		len(c.Hashes) != 1 || len(c.CPEs) != 1 || c.Confidence != nil {
		t.Errorf("fusion : %+v", c)
	}
}

func TestNormalizeHashAlgorithms(t *testing.T) {
	h := cleanHashes([]RawHash{
		{"SHA-512", strings.Repeat("A", 128)}, {"sha3_256", strings.Repeat("b", 64)},
		{"BLAKE2b-256", strings.Repeat("c", 64)}, {"md5", strings.Repeat("z", 32)},
	})
	want := []string{"blake2b-256:" + strings.Repeat("c", 64), "sha3-256:" + strings.Repeat("b", 64), "sha512:" + strings.Repeat("a", 128)}
	if !slices.Equal(h, want) {
		t.Errorf("empreintes %v", h)
	}
}

func TestCountsOf(t *testing.T) {
	c := CountsOf([]Component{{Origin: OriginSyft}, {Origin: OriginIA, WeakID: true}, {Origin: OriginIA}})
	if c != (Counts{Total: 3, Syft: 1, IA: 2, Weak: 1}) {
		t.Errorf("comptes %+v", c)
	}
	if len(Origins()) != 2 {
		t.Error("origines")
	}
}
