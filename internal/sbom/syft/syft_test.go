package syft

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"leblanc.io/open-go-sbom/internal/sbom"
	"leblanc.io/open-go-sbom/internal/sbom/schema"
)

var update = flag.Bool("update", false, "réécrit les fichiers attendus de testdata/sbom/golden")

const testdata = "../../../testdata/sbom"

var limits = sbom.Limits{MaxBytes: 16 << 20, MaxDepth: 64, MaxComponents: 10_000}

func read(t testing.TB, name string) (sbom.Header, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdata, name))
	if err != nil {
		t.Fatal(err)
	}
	h, err := sbom.Precheck(bytes.NewReader(data), limits)
	if err != nil {
		t.Fatalf("%s : %v", name, err)
	}
	return h, data
}

func decodeFile(t testing.TB, name string) sbom.Document {
	t.Helper()
	h, data := read(t, name)
	doc, err := Decode(h.Format, data)
	if err != nil {
		t.Fatalf("%s : %v", name, err)
	}
	return doc
}

// TestGolden compare le Document de chaque jeu d'essai à son fichier attendu
// (go test ./internal/sbom/syft -update pour les réécrire après un changement voulu).
func TestGolden(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(testdata, "*.json"))
	if err != nil || len(files) < 10 {
		t.Fatalf("jeux d'essai : %d, %v", len(files), err)
	}
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			doc := decodeFile(t, name)
			got, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join(testdata, "golden", strings.TrimSuffix(name, ".json")+".golden.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (go test -update pour le créer)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s diffère de %s (go test -update après vérification)", name, golden)
			}
		})
	}
}

func find(doc sbom.Document, name string) (sbom.Component, bool) {
	i := slices.IndexFunc(doc.Components, func(c sbom.Component) bool { return c.Name == name })
	if i < 0 {
		return sbom.Component{}, false
	}
	return doc.Components[i], true
}

func TestHostDistrosAndQualifiers(t *testing.T) {
	cases := []struct {
		file, distro, version, pkg string
		qualifiers                 []string
	}{
		{"debian-12.cdx15.json", "debian", "12", "zlib1g", []string{"arch=amd64", "distro=debian-12", "upstream=zlib"}},
		{"rhel-8.cdx16.json", "rhel", "8.6", "openssl-libs", []string{"arch=s390x", "distro=rhel-8.6", "epoch=1", "upstream=openssl-1.1.1k-6.el8_5.src.rpm"}},
		{"rhel-8.spdx23.json", "rhel", "8.6", "shadow-utils", []string{"arch=s390x", "epoch=2"}},
		{"alpine-3.20.syft.json", "alpine", "3.20.3", "libssl3", []string{"arch=x86_64", "distro=alpine-3.20.3", "upstream=openssl"}},
		{"alpine-3.20.spdx23.json", "alpine", "3.20.3", "busybox", []string{"arch=x86_64", "distro=alpine-3.20.3"}},
		{"ubuntu-24.04.cdx17.json", "ubuntu", "24.04", "libssl3t64", []string{"arch=amd64", "distro=ubuntu-24.04", "upstream=openssl"}},
		{"ubuntu-24.04.syft.json", "ubuntu", "24.04", "bsdutils", []string{"distro=ubuntu-24.04", "upstream=util-linux"}},
	}
	for _, tc := range cases {
		doc := decodeFile(t, tc.file)
		if doc.Distro == nil || doc.Distro.ID != tc.distro || doc.Distro.VersionID != tc.version {
			t.Errorf("%s : distribution %+v", tc.file, doc.Distro)
		}
		c, ok := find(doc, tc.pkg)
		if !ok {
			t.Fatalf("%s : %s absent", tc.file, tc.pkg)
		}
		for _, q := range tc.qualifiers {
			if !strings.Contains(c.PURL, q) {
				t.Errorf("%s : %s sans %s : %s", tc.file, tc.pkg, q, c.PURL)
			}
		}
		if len(c.CPEs) == 0 {
			t.Errorf("%s : %s sans CPE", tc.file, tc.pkg)
		}
		for _, x := range doc.Components {
			if x.WeakID || x.Origin != sbom.OriginSyft {
				t.Errorf("%s : %+v", tc.file, x)
			}
		}
	}
}

// Les trois formats d'un même inventaire donnent les mêmes purl canoniques.
func TestFormatsAgree(t *testing.T) {
	purls := func(name string) []string {
		var out []string
		for _, c := range decodeFile(t, name).Components {
			out = append(out, c.PURL)
		}
		return out
	}
	cdx := purls("ubuntu-24.04.cdx17.json")
	if len(cdx) != 24 {
		t.Fatalf("%d composants, attendu 24", len(cdx))
	}
	for _, other := range []string{"ubuntu-24.04.spdx23.json", "ubuntu-24.04.syft.json"} {
		if got := purls(other); !slices.Equal(got, cdx) {
			t.Errorf("%s diffère de CycloneDX :\n%v\n%v", other, got, cdx)
		}
	}
	if a, b := purls("alpine-3.20.syft.json"), purls("alpine-3.20.spdx23.json"); !slices.Equal(a, b) {
		t.Errorf("alpine : %v / %v", a, b)
	}
}

func TestOgsbomPropertiesAndEvidence(t *testing.T) {
	doc := decodeFile(t, "portail-client-ia.cdx16.json")
	jq, ok := find(doc, "jquery")
	if !ok {
		t.Fatal("jquery absent")
	}
	if jq.Origin != sbom.OriginIA || jq.Confidence == nil || *jq.Confidence != 0.82 || jq.Model != "example-model" ||
		jq.Scope != sbom.ScopeRequired || jq.PURL != "pkg:npm/jquery@3.4.1" || len(jq.Evidence) == 0 || len(jq.Hashes) != 1 {
		t.Errorf("jquery : %+v", jq)
	}
	foo, ok := find(doc, "libfoo-interne")
	if !ok || !foo.WeakID || foo.PURL != "pkg:generic/libfoo-interne@1.2" || foo.Origin != sbom.OriginIA || foo.Scope != sbom.ScopeOptional {
		t.Errorf("composant sans purl : %+v", foo)
	}
	ext, ok := find(doc, "Django_Extensions")
	if !ok || ext.PURL != "pkg:pypi/django-extensions@3.2.3?repository_url=https:%2F%2Fpypi.org%2Fsimple" {
		t.Errorf("purl canonicalisé : %+v", ext)
	}
	express, _ := find(doc, "express")
	if len(express.Hashes) != 1 || !strings.HasPrefix(express.Hashes[0], "sha512:") {
		t.Errorf("empreinte d'express : %v", express.Hashes)
	}
	if _, ok := find(doc, "portail-client"); !ok {
		t.Error("le paquet npm du dépôt est un composant")
	}
	counts := sbom.CountsOf(doc.Components)
	if counts.IA != 3 || counts.Weak != 1 || counts.Syft != 9 {
		t.Errorf("comptes %+v", counts)
	}
}

// Deux SBOM qui ne diffèrent que par l'horodatage et le numéro de série ont la même
// empreinte d'inventaire (critère de T05).
func TestFingerprintIgnoresTimestampAndSerial(t *testing.T) {
	h, data := read(t, "portail-client.cdx16.json")
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["serialNumber"] = "urn:uuid:00000000-1111-4222-8333-444444444444"
	m["metadata"].(map[string]any)["timestamp"] = "2030-01-01T00:00:00Z"
	other, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Decode(h.Format, data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Decode(h.Format, other)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(data, other) || sbom.Fingerprint(a.Components) != sbom.Fingerprint(b.Components) {
		t.Error("empreinte différente pour un simple changement d'horodatage et de numéro de série")
	}
	ia := decodeFile(t, "portail-client-ia.cdx16.json")
	if sbom.Fingerprint(a.Components) == sbom.Fingerprint(ia.Components) {
		t.Error("deux inventaires différents ont la même empreinte")
	}
}

func TestDecodeFailures(t *testing.T) {
	for _, tc := range []struct {
		format sbom.Format
		doc    string
		key    string
	}{
		{sbom.FormatCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":"x"}`, sbom.KeyDecodeFailed},
		{sbom.FormatSPDX, `{"spdxVersion":"SPDX-2.3","packages":"x"}`, sbom.KeyDecodeFailed},
		{sbom.FormatSyft, `{"artifacts":"x","schema":{"version":"16.1.0"}}`, sbom.KeyDecodeFailed},
		{sbom.Format("xml"), `<bom/>`, sbom.KeyUnsupportedFormat},
	} {
		_, err := Decode(tc.format, []byte(tc.doc))
		if e, ok := sbom.AsError(err); !ok || e.Key != tc.key {
			t.Errorf("%s : %v, attendu %s", tc.doc, err, tc.key)
		}
	}
}

// Le SBOM réencodé en CycloneDX 1.6 et en SPDX 2.3 est valide pour son format et garde
// l'inventaire (critère de T05).
func TestEncodeIsValid(t *testing.T) {
	v, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rhel-8.cdx16.json", "ubuntu-24.04.syft.json", "alpine-3.20.spdx23.json", "debian-12.cdx15.json"} {
		h, data := read(t, name)
		orig, err := Decode(h.Format, data)
		if err != nil {
			t.Fatal(err)
		}
		for target, want := range map[Target]struct {
			format  sbom.Format
			version string
		}{TargetCycloneDX16: {sbom.FormatCycloneDX, "1.6"}, TargetSPDX23: {sbom.FormatSPDX, "2.3"}} {
			var buf bytes.Buffer
			if err := Encode(&buf, h.Format, data, target, v.CycloneDXLicenseIDs("1.6")); err != nil {
				t.Fatalf("%s → %s : %v", name, target, err)
			}
			got, err := sbom.Precheck(bytes.NewReader(buf.Bytes()), limits)
			if err != nil || got.Format != want.format || got.SpecVersion != want.version {
				t.Fatalf("%s → %s : %+v, %v", name, target, got, err)
			}
			if err := v.ValidateStrict(got.Format, got.SpecVersion, buf.Bytes()); err != nil {
				t.Errorf("%s → %s invalide : %v", name, target, err)
			}
			again, err := Decode(got.Format, buf.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if len(again.Components) != len(orig.Components) {
				t.Errorf("%s → %s : %d composants au lieu de %d", name, target, len(again.Components), len(orig.Components))
			}
		}
	}
	if err := Encode(&bytes.Buffer{}, sbom.FormatCycloneDX, []byte(`{}`), TargetSPDX23, nil); err == nil {
		t.Error("document illisible réencodé")
	}
	_, data := read(t, "debian-12.cdx15.json")
	if err := Encode(&bytes.Buffer{}, sbom.FormatCycloneDX, data, Target("xml"), nil); err == nil {
		t.Error("cible inconnue acceptée")
	}
	// Sans réécriture, l'identifiant Artistic-dist (liste SPDX postérieure à CycloneDX
	// 1.6) rend le document invalide pour le schéma officiel.
	h, data := read(t, "ubuntu-24.04.syft.json")
	var raw bytes.Buffer
	if err := Encode(&raw, h.Format, data, TargetCycloneDX16, nil); err != nil {
		t.Fatal(err)
	}
	if err := v.ValidateStrict(sbom.FormatCycloneDX, "1.6", raw.Bytes()); err == nil {
		t.Error("le jeu d'essai ne couvre plus la réécriture des licences")
	}
	if err := v.Validate(sbom.FormatCycloneDX, "1.6", raw.Bytes()); err != nil {
		t.Errorf("validation des SBOM reçus trop stricte : %v", err)
	}
	if _, ok := ParseTarget("spdx-2.3"); !ok {
		t.Error("ParseTarget")
	}
	if _, ok := ParseTarget("cyclonedx-1.4"); ok {
		t.Error("ParseTarget accepte une cible inconnue")
	}
}

func FuzzDecode(f *testing.F) {
	for _, name := range []string{"debian-12.cdx15.json", "alpine-3.20.syft.json", "alpine-3.20.spdx23.json"} {
		data, err := os.ReadFile(filepath.Join(testdata, name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a","purl":"pkg:npm/a@1","properties":[{"name":"ogsbom:origin","value":"ia"}]}]}`))
	small := sbom.Limits{MaxBytes: 1 << 20, MaxDepth: 32, MaxComponents: 2000}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := sbom.Precheck(bytes.NewReader(data), small)
		if err != nil {
			return
		}
		doc, err := Decode(h.Format, data)
		if err != nil {
			if _, ok := sbom.AsError(err); !ok {
				t.Fatalf("erreur sans clé : %v", err)
			}
			return
		}
		for _, c := range doc.Components {
			if p, err := sbom.CanonicalPURL(c.PURL); err != nil || p.String != c.PURL {
				t.Fatalf("purl non canonique %q", c.PURL)
			}
		}
	})
}
