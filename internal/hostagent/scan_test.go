package hostagent

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

func testRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// testScanner inventorie testdata/rootfs, avec un montage NFS simulé et une exclusion
// configurée.
func testScanner(t *testing.T) SyftScanner {
	root := testRoot(t)
	return SyftScanner{Root: root, Hostname: "srv-test", Exclude: []string{"/srv/cache"}, Parallelism: 2, Version: "test",
		Mounts: func() []mount {
			return []mount{{Point: "/", FSType: "ext4"}, {Point: root, FSType: "overlay"},
				{Point: filepath.Join(root, "mnt/nfs"), FSType: "nfs4"}}
		}}
}

// TestScanFindsInstalledPackagesOnly : le SBOM de testdata/rootfs contient les paquets
// dpkg, rpm, apk et Python attendus, et rien des stockages de conteneurs, de /proc, d'un
// montage réseau ni d'une exclusion configurée.
func TestScanFindsInstalledPackagesOnly(t *testing.T) {
	inv, err := testScanner(t).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sbomsyft.Decode(sbom.FormatSyft, inv.SBOM)
	if err != nil {
		t.Fatal(err)
	}
	var purls []string
	for _, c := range doc.Components {
		purls = append(purls, c.PURL)
		if c.Version == "9.9.9" || strings.HasPrefix(c.Version, "9.9.9") {
			t.Errorf("paquet exclu inventorié : %s", c.PURL)
		}
	}
	for _, want := range []string{
		"pkg:deb/debian/base-files@12.4%2Bdeb12u7?arch=amd64&distro=debian-12",
		"pkg:deb/debian/libc6@2.36-9%2Bdeb12u8?arch=amd64&distro=debian-12&upstream=glibc",
		"pkg:deb/debian/openssl@3.0.14-1~deb12u2?arch=amd64&distro=debian-12",
		"pkg:apk/debian/musl@1.2.5-r0?arch=x86_64&distro=debian-12",
		"pkg:apk/debian/busybox@1.36.1-r29?arch=x86_64&distro=debian-12",
		"pkg:pypi/requests@2.31.0",
	} {
		if !slices.Contains(purls, want) {
			t.Errorf("%s absent du SBOM", want)
		}
	}
	if !slices.ContainsFunc(purls, func(p string) bool { return strings.HasPrefix(p, "pkg:rpm/") && strings.Contains(p, "/libuuid@") }) {
		t.Errorf("paquet rpm libuuid absent : %v", purls)
	}
	if inv.Components != len(doc.Components) || inv.Fingerprint != sbom.Fingerprint(doc.Components) || inv.Started.IsZero() {
		t.Errorf("inventaire %d composants, empreinte %x", inv.Components, inv.Fingerprint)
	}
	if strings.Contains(string(inv.SBOM), "docker-image-only") || strings.Contains(string(inv.SBOM), "rootless-image-only") {
		t.Error("le SBOM mentionne un paquet d'image de conteneur")
	}
	if t.Failed() {
		t.Logf("purl : %v", purls)
	}
}

// TestFingerprintIsStable : deux scans sans changement donnent la même empreinte, même si
// les documents diffèrent (horodatages, identifiants).
func TestFingerprintIsStable(t *testing.T) {
	s := testScanner(t)
	a, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("empreintes %x et %x", a.Fingerprint, b.Fingerprint)
	}
	s.Exclude = append(s.Exclude, "/lib/apk")
	c, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint == a.Fingerprint || c.Components != a.Components-2 {
		t.Errorf("sans les paquets apk : %d composants (%d avant), même empreinte : %v", c.Components, a.Components, c.Fingerprint == a.Fingerprint)
	}
}

func TestScanHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testScanner(t).Scan(ctx); err == nil {
		t.Error("scan annulé terminé sans erreur")
	}
}
