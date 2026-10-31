package grype

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"

	"leblanc.io/open-go-sbom/internal/vuln"
	"leblanc.io/open-go-sbom/internal/vuln/grype/grypetest"
)

// tinyArchive construit une vraie archive de base Grype v6, vide.
func tinyArchive(t *testing.T) string {
	t.Helper()
	path, err := grypetest.TinyArchive(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallOpenMatch(t *testing.T) {
	ctx := context.Background()
	e := NewEngine()
	dir := filepath.Join(t.TempDir(), "db")
	desc, err := e.Install(ctx, tinyArchive(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Built.IsZero() || !strings.HasPrefix(desc.Schema, "v6.") {
		t.Fatalf("description %+v", desc)
	}
	if _, err := e.Install(ctx, tinyArchive(t), dir); err == nil {
		t.Fatal("installation dans un répertoire existant acceptée")
	}
	d, err := e.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Description() != desc {
		t.Fatalf("description %+v, attendue %+v", d.Description(), desc)
	}
	sbom, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sbom", "log4shell.cdx16.json"))
	if err != nil {
		t.Fatal(err)
	}
	ms, vulns, err := d.Match(ctx, sbom)
	if err != nil || len(ms) != 0 || len(vulns) != 0 {
		t.Fatalf("base vide : %d correspondances, %v", len(ms), err)
	}
	if _, _, err := d.Match(ctx, []byte(`{"pas":"un sbom"}`)); err == nil {
		t.Fatal("document illisible accepté")
	}
}

func TestInstallRejectsCorruptArchive(t *testing.T) {
	ctx := context.Background()
	good, err := os.ReadFile(tinyArchive(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"tronquée":        good[:len(good)/2],
		"pas une archive": []byte("ceci n'est pas une archive"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.tar.gz")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "db")
			if _, err := NewEngine().Install(ctx, path, dir); err == nil {
				t.Fatal("archive corrompue installée")
			}
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("répertoire laissé après un refus : %v", err)
			}
		})
	}
	if _, err := NewEngine().Open(ctx, t.TempDir()); err == nil {
		t.Fatal("répertoire vide ouvert")
	}
}

type fakeFetcher map[string]string

func (f fakeFetcher) Fetch(_ context.Context, url string, w io.Writer, maxBytes int64) error {
	body, ok := f[url]
	if !ok {
		return errors.New("404")
	}
	if int64(len(body)) > maxBytes {
		return vuln.ErrTooLarge
	}
	_, err := io.WriteString(w, body)
	return err
}

const listing = `{"status":"active","schemaVersion":"v6.1.10","built":"2026-10-30T06:23:28Z",
 "path":"vulnerability-db_v6.1.10_2026-10-30T00:25:15Z_1793341408.tar.zst",
 "checksum":"sha256:1E1B9CF2CBFAF16B770E4D75D7BEB4840DC4254CA2281682FE5EC3700A4251A8"}`

func TestSource(t *testing.T) {
	ctx := context.Background()
	f := fakeFetcher{
		"https://grype.anchore.io/databases/v6/latest.json": listing,
		"https://mirror.example/grype/v6/latest.json":       listing,
	}
	s, err := NewSource(f, "")
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantURL := "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-10-30T00:25:15Z_1793341408.tar.zst?checksum=sha256%3A1E1B9CF2CBFAF16B770E4D75D7BEB4840DC4254CA2281682FE5EC3700A4251A8"
	if l.URL != wantURL || l.SHA256 != "1e1b9cf2cbfaf16b770e4d75d7beb4840dc4254ca2281682fe5ec3700a4251a8" ||
		l.Schema != "v6.1.10" || !l.Built.Equal(time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC)) {
		t.Fatalf("liste %+v", l)
	}
	f[l.URL] = "archive"
	var buf bytes.Buffer
	if err := s.Download(ctx, l, &buf, 100); err != nil || buf.String() != "archive" {
		t.Fatalf("téléchargement %q, %v", buf.String(), err)
	}
	if err := s.Download(ctx, l, io.Discard, 3); !errors.Is(err, vuln.ErrTooLarge) {
		t.Fatalf("borne ignorée : %v", err)
	}
	mirror, err := NewSource(f, "https://mirror.example/grype/")
	if err != nil {
		t.Fatal(err)
	}
	if l, err := mirror.Latest(ctx); err != nil || !strings.HasPrefix(l.URL, "https://mirror.example/grype/v6/vulnerability-db") {
		t.Fatalf("miroir : %+v, %v", l, err)
	}
}

func TestParseListingRejects(t *testing.T) {
	resolver, err := v6dist.NewClient(v6dist.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"illisible":     `{`,
		"vide":          `{}`,
		"autre schéma":  strings.Replace(listing, "v6.1.10\"", "v5.0.0\"", 1),
		"sans chemin":   strings.Replace(listing, `"path":"vulnerability-db_v6.1.10_2026-10-30T00:25:15Z_1793341408.tar.zst",`, "", 1),
		"somme md5":     strings.Replace(listing, "sha256:1E1B9CF2CBFAF16B770E4D75D7BEB4840DC4254CA2281682FE5EC3700A4251A8", "md5:abc", 1),
		"somme courte":  strings.Replace(listing, "1E1B9CF2CBFAF16B770E4D75D7BEB4840DC4254CA2281682FE5EC3700A4251A8", "1e1b", 1),
		"somme non hex": strings.Replace(listing, "1E1B9CF2CBFAF16B770E4D75D7BEB4840DC4254CA2281682FE5EC3700A4251A8", strings.Repeat("z", 64), 1),
	} {
		if _, err := parseListing([]byte(body), resolver); err == nil {
			t.Errorf("%s : liste acceptée", name)
		}
	}
}

func meta(id, ns, sev string) *vulnerability.Metadata {
	return &vulnerability.Metadata{ID: id, Namespace: ns, Severity: sev, Description: "d " + id,
		Cvss: []vulnerability.Cvss{{Source: ns, Type: "Primary", Version: "3.1", Vector: "CVSS:3.1/AV:N", Metrics: vulnerability.CvssMetrics{BaseScore: 9.8}}}}
}

func TestConvert(t *testing.T) {
	added := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	ghsa := meta("GHSA-jfh8-c2jp-5v3q", "github:language:java", "Critical")
	ghsa.KnownExploited = []vulnerability.KnownExploited{{CVE: "CVE-2021-44228", DateAdded: &added, KnownRansomwareCampaignUse: "Known"}}
	ghsa.EPSS = []vulnerability.EPSS{{CVE: "CVE-2021-44228", EPSS: 0.94, Percentile: 0.999}}
	log4j := pkg.Package{Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
	deb := pkg.Package{Name: "openssl", Version: "1:3.0", PURL: "pkg:deb/debian/openssl@1%3A3.0?distro=debian-12"}
	ms := []match.Match{
		{
			Package: log4j,
			Vulnerability: vulnerability.Vulnerability{
				Reference:              vulnerability.Reference{ID: "CVE-2021-44228", Namespace: "nvd:cpe"},
				RelatedVulnerabilities: []vulnerability.Reference{{ID: "GHSA-jfh8-c2jp-5v3q"}},
				Fix:                    vulnerability.Fix{Versions: []string{"2.15.0", " ", "2.15.0"}, State: vulnerability.FixStateFixed},
				Metadata:               ghsa,
			},
			Details: match.Details{{Type: match.CPEMatch}, {Type: match.ExactDirectMatch}},
		},
		{
			Package: deb,
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2024-5535", Namespace: "debian:distro:debian:12"},
				Fix:       vulnerability.Fix{State: vulnerability.FixStateWontFix},
				Metadata:  &vulnerability.Metadata{ID: "CVE-2024-5535", Severity: "Unknown"},
			},
			Details: match.Details{{Type: match.ExactIndirectMatch}},
		},
		{Package: deb, Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: strings.Repeat("X", 200)}}},
		{Package: pkg.Package{Name: "", PURL: "::"}, Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-1"}}},
	}
	nvd := map[string]*vulnerability.Metadata{
		"CVE-2021-44228": meta("CVE-2021-44228", "nvd:cpe", "Critical"),
		"CVE-2024-5535":  meta("CVE-2024-5535", "nvd:cpe", "High"),
	}
	nvd["CVE-2021-44228"].KnownExploited = ghsa.KnownExploited
	nvd["CVE-2021-44228"].URLs = []string{"https://b", "https://a", "https://a"}
	got, vulns, err := convert(ms, func(id string) *vulnerability.Metadata { return nvd[id] })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d correspondances : %+v", len(got), got)
	}
	l := got[0]
	if l.PURL != log4j.PURL || l.Type != vuln.MatchExactDirect || l.FixState != vuln.FixFixed ||
		len(l.FixedVersions) != 1 || l.Severity != vuln.SeverityCritical || l.Risk <= 0 {
		t.Fatalf("log4j %+v", l)
	}
	d := got[1]
	// Sévérité inconnue de la distribution : celle du catalogue (NVD).
	if d.PURL != "pkg:deb/debian/openssl@1:3.0?distro=debian-12" || d.Type != vuln.MatchExactIndirect ||
		d.FixState != vuln.FixWontFix || d.Severity != vuln.SeverityHigh {
		t.Fatalf("openssl %+v", d)
	}
	v := vulns["CVE-2021-44228"]
	if v.Namespace != "nvd:cpe" || v.KEV == nil || !v.KEV.Ransomware || !v.KEV.DateAdded.Equal(added) ||
		len(v.Aliases) != 1 || v.Aliases[0] != "GHSA-jfh8-c2jp-5v3q" || v.BaseScore() != 9.8 ||
		strings.Join(v.URLs, ",") != "https://a,https://b" || v.Risk <= 0 {
		t.Fatalf("catalogue %+v", v)
	}
	// Sans fiche NVD, la fiche de la correspondance.
	got, vulns, _ = convert(ms[:1], func(string) *vulnerability.Metadata { return nil })
	if vulns["CVE-2021-44228"].Namespace != "github:language:java" || vulns["CVE-2021-44228"].EPSS == nil || len(got) != 1 {
		t.Fatalf("repli sur la source : %+v", vulns["CVE-2021-44228"])
	}
	if e := catalogEntry("X", nil); e.Severity != vuln.SeverityUnknown || e.ID != "X" {
		t.Fatalf("sans métadonnées : %+v", e)
	}
}

func TestHelpers(t *testing.T) {
	if got := truncate("é\x00abc", 3); got != "éa" {
		t.Errorf("truncate : %q", got)
	}
	if got := truncate("ééé", 3); got != "é" {
		t.Errorf("truncate en milieu de caractère : %q", got)
	}
	long := make([]string, 40)
	for i := range long {
		long[i] = strings.Repeat("a", i+1)
	}
	if got := cleanList(append(long, "x\x00"), 100); len(got) != maxListLen {
		t.Errorf("cleanList : %d", len(got))
	}
	for s, want := range map[vulnerability.FixState]vuln.FixState{
		vulnerability.FixStateFixed: vuln.FixFixed, vulnerability.FixStateNotFixed: vuln.FixNotFixed,
		vulnerability.FixStateWontFix: vuln.FixWontFix, vulnerability.FixStateUnknown: vuln.FixUnknown,
	} {
		if fixState(s) != want {
			t.Errorf("fixState(%s)", s)
		}
	}
	if bestType(nil) != vuln.MatchCPE {
		t.Error("bestType sans détail")
	}
	if latestURL("https://x/y.json") != "https://x/y.json" || latestURL("https://x/") != "https://x/v6/latest.json" {
		t.Error("latestURL")
	}
}
