//go:build grypedb

package grype

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"leblanc.io/lotor/internal/vuln"
)

// openReal ouvre la base réelle désignée par LOTOR_TEST_GRYPEDB_DIR (répertoire racine
// d'une base Grype v6 installée, qui contient 6/vulnerability.db).
func openReal(t *testing.T) vuln.Database {
	t.Helper()
	dir := os.Getenv("LOTOR_TEST_GRYPEDB_DIR")
	if dir == "" {
		t.Fatal("LOTOR_TEST_GRYPEDB_DIR : répertoire d'une base Grype v6 installée")
	}
	d, err := NewEngine().Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func readSBOM(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRealLog4Shell(t *testing.T) {
	d := openReal(t)
	ms, vulns, err := d.Match(context.Background(), readSBOM(t, "log4shell.cdx16.json"))
	if err != nil {
		t.Fatal(err)
	}
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	i := slices.IndexFunc(ms, func(m vuln.Match) bool { return m.VulnerabilityID == "CVE-2021-44228" })
	if i < 0 {
		t.Fatalf("CVE-2021-44228 absent de %d correspondances", len(ms))
	}
	m := ms[i]
	if m.PURL != purl || !slices.Contains(m.FixedVersions, "2.15.0") || m.Severity != vuln.SeverityCritical {
		t.Fatalf("correspondance %+v", m)
	}
	v := vulns["CVE-2021-44228"]
	if v.KEV == nil || v.EPSS == nil || v.EPSS.Score < 0.5 || v.BaseScore() != 10 || !slices.Contains(v.Aliases, "GHSA-jfh8-c2jp-5v3q") {
		t.Fatalf("fiche %+v", v)
	}
	if !strings.HasPrefix(v.Namespace, "nvd") || v.Description == "" || v.Risk < 90 {
		t.Fatalf("fiche NVD attendue : %+v", v)
	}
	// Log4Shell ne touche que log4j-core : log4j-api, de même version, n'est pas concerné.
	for _, m := range ms {
		if m.VulnerabilityID == "CVE-2021-44228" && m.PURL != purl {
			t.Errorf("CVE-2021-44228 rattachée à %s", m.PURL)
		}
	}
}

// TestRealDebian vérifie que distribution et paquets sources arrivent jusqu'à Grype : les
// correspondances viennent de l'espace de noms Debian 12, y compris pour libcurl4 et
// libssl3, rattachées par leur paquet source (curl, openssl).
func TestRealDebian(t *testing.T) {
	d := openReal(t)
	ms, vulns, err := d.Match(context.Background(), readSBOM(t, "debian-12.cdx15.json"))
	if err != nil {
		t.Fatal(err)
	}
	byPkg := map[string]int{}
	for _, m := range ms {
		name := strings.SplitN(strings.TrimPrefix(m.PURL, "pkg:deb/debian/"), "@", 2)[0]
		byPkg[name]++
		if !strings.HasPrefix(m.PURL, "pkg:deb/debian/") || !strings.Contains(m.PURL, "distro=debian-12") {
			t.Errorf("purl inattendu %s", m.PURL)
		}
		if m.Type != vuln.MatchExactDirect && m.Type != vuln.MatchExactIndirect {
			t.Errorf("%s : correspondance %s, attendue par l'écosystème deb", m.VulnerabilityID, m.Type)
		}
	}
	for _, p := range []string{"openssl", "libssl3", "curl", "libcurl4", "libc6", "tar"} {
		if byPkg[p] == 0 {
			t.Errorf("aucun constat pour %s (%v)", p, byPkg)
		}
	}
	// CVE-2024-5535 (openssl, corrigée en 3.0.15-1~deb12u1) touche openssl et libssl3,
	// paquet binaire de la source openssl.
	for _, p := range []string{"openssl", "libssl3"} {
		if !slices.ContainsFunc(ms, func(m vuln.Match) bool {
			return m.VulnerabilityID == "CVE-2024-5535" && strings.Contains(m.PURL, "/"+p+"@")
		}) {
			t.Errorf("CVE-2024-5535 attendue sur %s", p)
		}
	}
	if len(vulns) == 0 {
		t.Fatal("catalogue vide")
	}
	t.Logf("%d correspondances, %d vulnérabilités, par paquet : %v", len(ms), len(vulns), byPkg)
}

// TestRealConcurrent : la base ouverte sert plusieurs correspondances à la fois (workers).
func TestRealConcurrent(t *testing.T) {
	d := openReal(t)
	blob := readSBOM(t, "debian-12.cdx15.json")
	want, _, err := d.Match(context.Background(), blob)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			got, _, err := d.Match(context.Background(), blob)
			if err != nil || len(got) != len(want) {
				t.Errorf("correspondance concurrente : %d au lieu de %d (%v)", len(got), len(want), err)
			}
		})
	}
	wg.Wait()
}
