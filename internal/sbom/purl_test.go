package sbom

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalPURL(t *testing.T) {
	cases := []struct {
		name, in, want, base string
	}{
		{"déjà canonique", "pkg:deb/debian/openssl@3.0.14-1~deb12u2?arch=amd64&distro=debian-12",
			"pkg:deb/debian/openssl@3.0.14-1~deb12u2?arch=amd64&distro=debian-12", "pkg:deb/debian/openssl"},
		{"qualificatifs triés et clés en minuscules", "pkg:rpm/redhat/tar@1.30-5.el8?UPSTREAM=tar-1.30-5.el8.src.rpm&epoch=2&arch=s390x&distro=rhel-8.6",
			"pkg:rpm/redhat/tar@1.30-5.el8?arch=s390x&distro=rhel-8.6&epoch=2&upstream=tar-1.30-5.el8.src.rpm", "pkg:rpm/redhat/tar"},
		{"schéma et type en minuscules", "PKG:NPM/jquery@3.4.1", "pkg:npm/jquery@3.4.1", "pkg:npm/jquery"},
		{"pypi : minuscules et tiret", "pkg:pypi/Django_Extensions@3.2.3", "pkg:pypi/django-extensions@3.2.3", "pkg:pypi/django-extensions"},
		{"golang en minuscules", "pkg:golang/github.com/BurntSushi/toml@v1.3.2", "pkg:golang/github.com/burntsushi/toml@v1.3.2", "pkg:golang/github.com/burntsushi/toml"},
		{"deb : espace de noms en minuscules", "pkg:deb/Ubuntu/zlib1g@1:1.3.dfsg-3.1ubuntu2.3?arch=amd64&distro=ubuntu-24.04",
			"pkg:deb/ubuntu/zlib1g@1:1.3.dfsg-3.1ubuntu2.3?arch=amd64&distro=ubuntu-24.04", "pkg:deb/ubuntu/zlib1g"},
		{"encodage unique de la version", "pkg:deb/debian/login@1%3a4.13%2bdfsg1-1%2bb1", "pkg:deb/debian/login@1:4.13%2Bdfsg1-1%2Bb1", "pkg:deb/debian/login"},
		{"maven garde sa casse", "pkg:maven/org.Apache.Logging/Log4j-Core@2.17.1", "pkg:maven/org.Apache.Logging/Log4j-Core@2.17.1", "pkg:maven/org.Apache.Logging/Log4j-Core"},
		{"npm à portée", "pkg:npm/%40babel/runtime@7.24.7", "pkg:npm/%40babel/runtime@7.24.7", "pkg:npm/%40babel/runtime"},
		{"qualificatif vide retiré", "pkg:pypi/requests@2.31.0?Arch=&repository_url=https://pypi.org/simple",
			"pkg:pypi/requests@2.31.0?repository_url=https:%2F%2Fpypi.org%2Fsimple", "pkg:pypi/requests"},
		{"sous-chemin nettoyé", "pkg:golang/golang.org/x/text@v0.14.0#/unicode/norm/", "pkg:golang/golang.org/x/text@v0.14.0#unicode/norm", "pkg:golang/golang.org/x/text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := CanonicalPURL(tc.in)
			if err != nil {
				t.Fatalf("CanonicalPURL(%q) : %v", tc.in, err)
			}
			if p.String != tc.want || p.Base != tc.base {
				t.Errorf("CanonicalPURL(%q) = %q, base %q ; attendu %q, base %q", tc.in, p.String, p.Base, tc.want, tc.base)
			}
			again, err := CanonicalPURL(p.String)
			if err != nil || again.String != p.String {
				t.Errorf("non idempotent : %q → %q (%v)", p.String, again.String, err)
			}
		})
	}
}

func TestCanonicalPURLKeepsIdentityQualifiers(t *testing.T) {
	p, err := CanonicalPURL("pkg:rpm/redhat/openssl-libs@1.1.1k-6.el8_5?arch=s390x&distro=rhel-8.6&epoch=1&upstream=openssl-1.1.1k-6.el8_5.src.rpm")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"arch=s390x", "distro=rhel-8.6", "epoch=1", "upstream=openssl-1.1.1k-6.el8_5.src.rpm"} {
		if !strings.Contains(p.String, q) {
			t.Errorf("qualificatif %q perdu : %s", q, p.String)
		}
	}
}

func TestCanonicalPURLRejects(t *testing.T) {
	for _, in := range []string{
		"", "openssl", "pkg:", "pkg:deb", "pkg:deb/", "pkg:1bad/name", "pkg:npm/foo?=x",
		"pkg:npm/foo?a=1&A=2", "pkg:npm/fo\x00o", "pkg:npm/" + strings.Repeat("a", MaxPURLLen),
		"pkg:npm/\xff\xfe",
	} {
		if _, err := CanonicalPURL(in); !errors.Is(err, ErrInvalidPURL) {
			t.Errorf("CanonicalPURL(%q) : erreur %v, attendu ErrInvalidPURL", in, err)
		}
	}
}

func TestComponentPURLGeneric(t *testing.T) {
	p, weak, err := ComponentPURL("", "libfoo interne", "1.2")
	if err != nil || !weak {
		t.Fatalf("ComponentPURL : %v, faible %v", err, weak)
	}
	if p.String != "pkg:generic/libfoo%20interne@1.2" || p.Base != "pkg:generic/libfoo%20interne" || p.Type != "generic" {
		t.Errorf("purl générique %+v", p)
	}
	p, weak, err = ComponentPURL("pas un purl", "libfoo", "")
	if err != nil || !weak || p.String != "pkg:generic/libfoo" {
		t.Errorf("purl illisible : %+v, %v, %v", p, weak, err)
	}
	if _, _, err := ComponentPURL("", "", "1.0"); !errors.Is(err, ErrInvalidPURL) {
		t.Errorf("sans nom ni purl : %v", err)
	}
	p, weak, err = ComponentPURL("pkg:npm/lodash@4.17.21", "lodash", "4.17.21")
	if err != nil || weak || p.String != "pkg:npm/lodash@4.17.21" {
		t.Errorf("purl utilisable : %+v, %v, %v", p, weak, err)
	}
}
