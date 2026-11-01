package vex

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/triage"
)

var (
	when  = time.Date(2026, 10, 30, 14, 20, 0, 0, time.UTC)
	until = time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC)
	meta  = Meta{ID: uuid.MustParse("019a3f2e-0000-7000-8000-000000000001"), Author: "Atelier Nord", Tooling: "lotor 0.2.0", Time: when}
)

const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

// sample couvre chaque statut et chaque justification des deux listes.
func sample() []triage.Statement {
	out := []triage.Statement{
		{VulnID: "CVE-2021-0001", PURL: log4j, Status: triage.StatusInTriage, Comment: "En cours d'examen.", Time: when},
		{VulnID: "CVE-2021-0002", PURL: log4j, Status: triage.StatusAffected, Comment: "Correctif prévu en 4.2.", Time: when},
		{VulnID: "CVE-2021-0003", PURL: log4j, Status: triage.StatusFalsePositive, Comment: "Mauvaise version détectée.", Time: when},
		{VulnID: "CVE-2021-0004", PURL: log4j, Status: triage.StatusRiskAccepted, Comment: "Réseau isolé.", ExpiresOn: &until, Time: when},
		{VulnID: "CVE-2021-0005", PURL: "pkg:npm/lodash@4.17.20", Status: triage.StatusFixed, Comment: "", Time: when},
		{VulnID: "CVE-2021-0006", PURL: "pkg:npm/lodash@4.17.20", Status: triage.StatusAffected, Comment: "", Time: when},
	}
	for i, j := range append(triage.OpenVEXJustifications(), triage.CycloneDXJustifications()...) {
		out = append(out, triage.Statement{VulnID: "CVE-2022-" + strings.Repeat("0", 3) + string(rune('a'+i)), PURL: log4j,
			Status: triage.StatusNotAffected, Justification: j, Comment: "Justifié : " + string(j), Time: when})
	}
	out = append(out, triage.Statement{VulnID: "CVE-2023-0001", PURL: log4j, Status: triage.StatusNotAffected,
		Comment: "Impact seul, sans justification.", Time: when})
	return out
}

func validators(t *testing.T) (*OpenVEXValidator, *schema.Validator) {
	t.Helper()
	ov, err := NewOpenVEXValidator()
	if err != nil {
		t.Fatal(err)
	}
	cv, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	return ov, cv
}

// TestExportsValidAgainstSchemas : les deux exports sont valides contre les schémas
// officiels (OpenVEX 0.2.0, CycloneDX 1.6 strict).
func TestExportsValidAgainstSchemas(t *testing.T) {
	ov, cv := validators(t)
	o, err := Encode(FormatOpenVEX, meta, sample())
	if err != nil {
		t.Fatal(err)
	}
	if err := ov.Validate(o); err != nil {
		t.Fatalf("OpenVEX invalide : %v\n%s", err, o)
	}
	c, err := Encode(FormatCycloneDX, meta, sample())
	if err != nil {
		t.Fatal(err)
	}
	if err := cv.ValidateStrict(sbom.FormatCycloneDX, "1.6", c); err != nil {
		t.Fatalf("CycloneDX invalide : %v\n%s", err, c)
	}
	// Le validateur refuse bien un document non conforme.
	if err := ov.Validate([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)); err == nil {
		t.Fatal("document OpenVEX incomplet accepté")
	}
}

// TestRoundTripSameFormat : export puis import dans le même format redonne les mêmes
// déclarations, justifications comprises.
func TestRoundTripSameFormat(t *testing.T) {
	for _, f := range Formats() {
		t.Run(string(f), func(t *testing.T) {
			data, err := Encode(f, meta, sample())
			if err != nil {
				t.Fatal(err)
			}
			doc, err := Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Format != f || doc.Author != meta.Author || doc.Skipped != 0 {
				t.Fatalf("format %s, auteur %q, écartées %d", doc.Format, doc.Author, doc.Skipped)
			}
			assertSame(t, sample(), doc.Statements)
		})
	}
}

// TestRoundTripAcrossFormats : d'un format à l'autre et retour, la justification
// d'origine revient grâce à la marque posée quand la correspondance la perd.
func TestRoundTripAcrossFormats(t *testing.T) {
	for _, pair := range [][2]Format{{FormatOpenVEX, FormatCycloneDX}, {FormatCycloneDX, FormatOpenVEX}} {
		first, err := Encode(pair[0], meta, sample())
		if err != nil {
			t.Fatal(err)
		}
		d1, err := Decode(first)
		if err != nil {
			t.Fatal(err)
		}
		second, err := Encode(pair[1], meta, d1.Statements)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := Decode(second)
		if err != nil {
			t.Fatal(err)
		}
		assertSame(t, sample(), d2.Statements)
	}
}

// TestForeignJustificationIsNoted : une justification de l'autre liste est traduite et
// notée ; une justification de la liste du format ne l'est pas.
func TestForeignJustificationIsNoted(t *testing.T) {
	st := func(j triage.Justification) []triage.Statement {
		return []triage.Statement{{VulnID: "CVE-1", PURL: log4j, Status: triage.StatusNotAffected, Justification: j, Time: when}}
	}
	o, _ := Encode(FormatOpenVEX, meta, st(triage.JustProtectedAtRuntime))
	if !bytes.Contains(o, []byte(`"justification": "inline_mitigations_already_exist"`)) ||
		!bytes.Contains(o, []byte("[lotor:justification=protected_at_runtime]")) {
		t.Fatalf("OpenVEX sans justification d'origine :\n%s", o)
	}
	o, _ = Encode(FormatOpenVEX, meta, st(triage.JustVulnerableCodeNotPresent))
	if bytes.Contains(o, []byte("lotor:")) {
		t.Fatalf("marque inutile pour une justification d'OpenVEX :\n%s", o)
	}
	c, _ := Encode(FormatCycloneDX, meta, st(triage.JustComponentNotPresent))
	if !bytes.Contains(c, []byte(`"lotor:triage_justification"`)) || !bytes.Contains(c, []byte(`"code_not_present"`)) {
		t.Fatalf("CycloneDX sans justification d'origine :\n%s", c)
	}
}

func assertSame(t *testing.T, want, got []triage.Statement) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d déclarations, attendu %d", len(got), len(want))
	}
	idx := map[string]triage.Statement{}
	for _, s := range got {
		idx[s.VulnID+"|"+s.PURL] = s
	}
	for _, w := range want {
		g, ok := idx[w.VulnID+"|"+w.PURL]
		if !ok {
			t.Errorf("%s %s absente", w.VulnID, w.PURL)
			continue
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s : %+v\nattendu %+v", w.VulnID, g, w)
		}
	}
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecodeVendorOpenVEX : VEX d'éditeur OpenVEX (sous-composants, purl en
// identifiers, produit sans version, produit sans purl écarté).
func TestDecodeVendorOpenVEX(t *testing.T) {
	doc, err := Decode(read(t, "vendor-openvex.json"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != FormatOpenVEX || doc.Author != "Vendor Example Security <security@vendor.example>" || doc.Skipped != 1 {
		t.Fatalf("%s %q écartées %d", doc.Format, doc.Author, doc.Skipped)
	}
	t21 := time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC)
	t20 := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	assertSame(t, []triage.Statement{
		{VulnID: "CVE-2021-44228", PURL: "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", Status: triage.StatusNotAffected,
			Justification: triage.JustVulnerableCodeNotInExecPath, Comment: "JNDI lookups are disabled by configuration.", Time: t21},
		{VulnID: "CVE-2021-44228", PURL: log4j, Status: triage.StatusNotAffected,
			Justification: triage.JustVulnerableCodeNotInExecPath, Comment: "JNDI lookups are disabled by configuration.", Time: t21},
		{VulnID: "CVE-2022-0001", PURL: "pkg:npm/lodash@4.17.20", Status: triage.StatusAffected, Comment: "Upgrade to 4.17.21.", Time: t20},
		{VulnID: "CVE-2022-0002", PURL: "pkg:npm/lodash", Status: triage.StatusInTriage, Time: t20},
		{VulnID: "CVE-2022-0003", PURL: "pkg:npm/lodash@4.17.20", Status: triage.StatusFixed, Comment: "Backported in our build.", Time: t20},
	}, doc.Statements)
}

// TestDecodeVendorCycloneDX : VEX d'éditeur CycloneDX 1.5 (références par bom-ref ou
// purl, vulnérabilité sans analyse et composant sans purl écartés).
func TestDecodeVendorCycloneDX(t *testing.T) {
	doc, err := Decode(read(t, "vendor-cyclonedx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != FormatCycloneDX || doc.Author != "Vendor Example" || doc.Skipped != 2 {
		t.Fatalf("%s %q écartées %d", doc.Format, doc.Author, doc.Skipped)
	}
	t20 := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	assertSame(t, []triage.Statement{
		{VulnID: "CVE-2021-44228", PURL: log4j, Status: triage.StatusNotAffected, Justification: triage.JustProtectedAtRuntime,
			Comment: "Mitigated by the JVM flag.", Time: time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC)},
		{VulnID: "CVE-2022-0001", PURL: "pkg:npm/lodash@4.17.20", Status: triage.StatusAffected, Comment: "Upgrade planned.", Time: t20},
		{VulnID: "CVE-2022-0003", PURL: "pkg:npm/lodash@4.17.20", Status: triage.StatusFixed, Time: t20},
	}, doc.Statements)
}

func TestDecodeRejects(t *testing.T) {
	for name, data := range map[string][]byte{
		"pas du JSON":     []byte("<vex/>"),
		"format inconnu":  []byte(`{"spdxVersion":"SPDX-2.3"}`),
		"OpenVEX abîmé":   []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":{}}`),
		"CycloneDX abîmé": []byte(`{"bomFormat":"CycloneDX","vulnerabilities":"x"}`),
	} {
		if _, err := Decode(data); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s : %v", name, err)
		}
	}
	if _, err := Decode(make([]byte, MaxDocument+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("document trop gros : %v", err)
	}
	// Plus de déclarations que la borne, produits développés.
	products := make([]map[string]string, triage.MaxImportStatements+1)
	for i := range products {
		products[i] = map[string]string{"@id": "pkg:npm/p" + strings.Repeat("x", i%7) + "@1.0." + string(rune('0'+i%10)) + "-" + itoa(i)}
	}
	body, _ := json.Marshal(map[string]any{"@context": OpenVEXContext, "statements": []any{map[string]any{
		"vulnerability": map[string]string{"name": "CVE-1"}, "status": "fixed", "products": products}}})
	if _, err := Decode(body); !errors.Is(err, ErrTooManyStatements) {
		t.Fatalf("trop de déclarations : %v", err)
	}
	if _, err := Encode(FormatOpenVEX, meta, nil); !errors.Is(err, ErrNoStatement) {
		t.Fatalf("export vide : %v", err)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestNotes(t *testing.T) {
	marks, text := readNotes("[lotor:status=risk_accepted;expires=2027-03-31] Réseau isolé.")
	if marks["status"] != "risk_accepted" || marks["expires"] != "2027-03-31" || text != "Réseau isolé." {
		t.Fatalf("%v %q", marks, text)
	}
	if marks, text := readNotes("[lotor:sans fin"); len(marks) != 0 || text != "[lotor:sans fin" {
		t.Fatalf("%v %q", marks, text)
	}
	if got := writeNotes(nil, "texte"); got != "texte" {
		t.Fatal(got)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-1"},"status":"fixed","products":[{"@id":"pkg:npm/a@1"}]}]}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"in_triage"},"affects":[{"ref":"pkg:npm/a@1"}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Decode(data)
		if err != nil {
			return
		}
		for _, s := range doc.Statements {
			if _, err := triage.ParseStatus(string(s.Status)); err != nil {
				t.Fatalf("statut %q", s.Status)
			}
			if s.Justification != "" && s.Status != triage.StatusNotAffected {
				t.Fatalf("justification %q pour %q", s.Justification, s.Status)
			}
		}
	})
}
