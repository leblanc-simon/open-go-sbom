package sbom

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testLimits = Limits{MaxBytes: 1 << 20, MaxDepth: 16, MaxComponents: 100}

func precheck(s string, l Limits) (Header, error) {
	return Precheck(strings.NewReader(s), l)
}

func wantKey(t *testing.T, err error, key string) {
	t.Helper()
	e, ok := AsError(err)
	if !ok || e.Key != key {
		t.Fatalf("erreur %v, attendu la clé %s", err, key)
	}
}

func TestPrecheckFormats(t *testing.T) {
	cases := []struct {
		doc     string
		format  Format
		version string
	}{
		{`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`, FormatCycloneDX, "1.5"},
		{`{"$schema":"x","BOMFORMAT":"CycloneDX","specversion":"1.7"}`, FormatCycloneDX, "1.7"},
		{`{"spdxVersion":"SPDX-2.3","packages":[{"name":"a"}]}`, FormatSPDX, "2.3"},
		{`{"artifacts":[{}],"schema":{"version":"16.1.11","url":"u"},"source":{}}`, FormatSyft, "16.1.11"},
		{"\n {\"bomFormat\" : \"Cyclone\\u0044X\", \"specVersion\": \"1.6\"}\n", FormatCycloneDX, "1.6"},
	}
	for _, tc := range cases {
		h, err := precheck(tc.doc, testLimits)
		if err != nil {
			t.Fatalf("%s : %v", tc.doc, err)
		}
		if h.Format != tc.format || h.SpecVersion != tc.version || h.Bytes != int64(len(tc.doc)) {
			t.Errorf("%s : %+v", tc.doc, h)
		}
	}
}

func TestPrecheckUnsupported(t *testing.T) {
	for _, doc := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.4"}`,
		`{"bomFormat":"CycloneDX","specVersion":1.6}`,
		`{"bomFormat":"Autre","specVersion":"1.6"}`,
		`{"spdxVersion":"SPDX-2.2"}`,
		`{"artifacts":[]}`,
		`{"schema":{"version":"16"}}`,
		`{}`,
		`<?xml version="1.0"?><bom/>`,
		`[{"bomFormat":"CycloneDX"}]`,
		`"texte"`,
	} {
		_, err := precheck(doc, testLimits)
		wantKey(t, err, KeyUnsupportedFormat)
	}
}

func TestPrecheckMalformed(t *testing.T) {
	for _, doc := range []string{
		``, `   `, `{`, `{"a"}`, `{"a":}`, `{"a":1,}`, `{"a":[1,]}`, `{"a":01}`, `{"a":1.}`, `{"a":-}`,
		`{"a":1e}`, `{"a":tru}`, `{"a":nul}`, `{"a":"\x01"}`, `{"a":"\q"}`, `{"a":"\u12g4"}`, `{"a":"x}`,
		`{a:1}`, `{"a":1}{}`, `{"a":1} x`, `{"a" 1}`, `{"a":[1 2]}`, `{"a":truex}`, `{"a":{"b":1 "c":2}}`,
	} {
		_, err := precheck(doc, testLimits)
		wantKey(t, err, KeyMalformed)
	}
}

func TestPrecheckValidScalars(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","n":[0,-1,2.5,-0.5e10,3E+2,1e-3,true,false,null,"é\"\\\/\b\f\n\r\té😀"],"o":{}}`
	if _, err := precheck(doc, testLimits); err != nil {
		t.Fatal(err)
	}
}

func TestPrecheckTooLarge(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","x":"` + strings.Repeat("a", 100) + `"}`
	l := testLimits
	l.MaxBytes = int64(len(doc))
	if _, err := precheck(doc, l); err != nil {
		t.Fatalf("à la borne exacte : %v", err)
	}
	l.MaxBytes--
	h, err := precheck(doc, l)
	wantKey(t, err, KeyTooLarge)
	if h.Bytes > l.MaxBytes {
		t.Errorf("lu %d octets au-delà de la borne %d", h.Bytes, l.MaxBytes)
	}
}

// endless est un flux infini : Precheck doit s'arrêter à la borne sans tout lire.
type endless struct{ n int64 }

func (e *endless) Read(p []byte) (int, error) {
	if e.n == 0 {
		copy(p, `{"bomFormat":"CycloneDX","x":"`)
		e.n = 1
		return 30, nil
	}
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestPrecheckStopsReadingAtBound(t *testing.T) {
	l := testLimits
	l.MaxBytes = 1 << 16
	_, err := Precheck(&endless{}, l)
	wantKey(t, err, KeyTooLarge)
}

func TestPrecheckTooDeep(t *testing.T) {
	l := testLimits
	l.MaxDepth = 4
	ok := `{"bomFormat":"CycloneDX","specVersion":"1.6","a":[{"b":[]}]}`
	h, err := precheck(ok, l)
	if err != nil || h.Depth != 4 {
		t.Fatalf("profondeur 4 : %+v, %v", h, err)
	}
	_, err = precheck(`{"a":[{"b":[[]]}]}`, l)
	wantKey(t, err, KeyTooDeep)
	// Une profondeur démesurée échoue à la borne, sans pile démesurée.
	_, err = precheck(`{"a":`+strings.Repeat("[", 1_000_000), l)
	wantKey(t, err, KeyTooDeep)
}

func TestPrecheckTooManyComponents(t *testing.T) {
	l := testLimits
	l.MaxComponents = 4
	nested := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"components":[{}]},{}],"metadata":{"component":{"components":[{}]}}}`
	h, err := precheck(nested, l)
	if err != nil || h.Components != 4 {
		t.Fatalf("composants imbriqués : %+v, %v", h, err)
	}
	for _, doc := range []string{
		`{"components":[1,2,3,4,5]}`,
		`{"Components":[1,2],"COMPONENTS":[3,4,5]}`,
		`{"components":[1,2,3,4,5]}`,
		`{"packages":[{},{},{},{},{}]}`,
		`{"artifacts":[{},{},{},{},{}]}`,
	} {
		_, err := precheck(doc, l)
		wantKey(t, err, KeyTooManyComponents)
	}
}

func TestPrecheckRejectsBadLimits(t *testing.T) {
	if _, err := precheck(`{}`, Limits{}); err == nil {
		t.Fatal("bornes nulles acceptées")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("flux corrompu") }

func TestPrecheckReadError(t *testing.T) {
	_, err := Precheck(io.MultiReader(strings.NewReader(`{"a":`), failingReader{}), testLimits)
	wantKey(t, err, KeyMalformed)
}

func TestPrecheckTestdata(t *testing.T) {
	files, err := filepath.Glob("../../testdata/sbom/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("jeux d'essai : %v", err)
	}
	l := Limits{MaxBytes: 16 << 20, MaxDepth: 64, MaxComponents: 10_000}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		h, err := Precheck(bytes.NewReader(data), l)
		if err != nil {
			t.Errorf("%s : %v", f, err)
			continue
		}
		if h.Components == 0 || h.Format == "" {
			t.Errorf("%s : %+v", f, h)
		}
	}
}

func TestErrorFormatting(t *testing.T) {
	cause := errors.New("cause")
	e := Reject(KeySchemaInvalid, "/components/0", cause)
	if !strings.Contains(e.Error(), "/components/0") || !errors.Is(e, cause) {
		t.Errorf("erreur %v", e)
	}
	if len(ErrorKeys()) != 7 {
		t.Error("clés d'erreur")
	}
	if printable("1.4\x00\xff"+strings.Repeat("x", 20)) != "1.4??"+strings.Repeat("x", 11) {
		t.Errorf("printable %q", printable("1.4\x00\xff"+strings.Repeat("x", 20)))
	}
}
