package grypeversion

import (
	"errors"
	"testing"

	"leblanc.io/open-go-sbom/internal/version"
)

// TestCompareByEcosystem : tables de comparaison par écosystème. Chaque ligne a < b selon
// la règle de son écosystème (et b > a, a = a) ; plusieurs lignes sont fausses en ordre
// lexical, ce qui prouve qu'aucune comparaison n'est textuelle.
func TestCompareByEcosystem(t *testing.T) {
	cases := map[version.Scheme][][2]string{
		version.SchemeNPM: {
			{"4.17.20", "4.17.21"}, {"4.9.0", "4.17.21"}, {"1.0.0-beta.2", "1.0.0-beta.11"},
			{"1.0.0-rc.1", "1.0.0"}, {"0.9.9", "1.0.0"},
		},
		version.SchemeMaven: {
			{"2.9.1", "2.17.1"}, {"2.14.1", "2.15.0"}, {"1.0-alpha-1", "1.0"}, {"1.0-beta", "1.0-rc1"},
			{"1.0", "1.0-sp1"}, {"1.0.0-SNAPSHOT", "1.0.0"},
		},
		version.SchemePyPI: {
			{"1.0.dev1", "1.0a1"}, {"1.0a1", "1.0b1"}, {"1.0rc1", "1.0"}, {"1.0", "1.0.post1"},
			{"1.9", "1.10"}, {"1!0.1", "1!0.2"}, {"2.0", "1!0.1"},
		},
		version.SchemeGem: {
			{"1.0.0.pre", "1.0.0"}, {"1.9.0", "1.10.0"}, {"1.0.0.rc1", "1.0.0.rc2"},
		},
		version.SchemeGolang: {
			{"v1.2.3", "v1.10.0"}, {"v0.0.0-20200101000000-abcdefabcdef", "v0.1.0"},
			{"v1.0.0-rc.1", "v1.0.0"}, {"v2.0.0+incompatible", "v2.1.0+incompatible"},
		},
		version.SchemeDebian: {
			{"1.0~rc1", "1.0"}, {"2.0", "1:1.0"}, {"1.2.3-1", "1.2.3-10"}, {"3.0.11-1~deb12u1", "3.0.11-1~deb12u2"},
			{"1.2.3-1", "1.2.3-1+deb12u1"},
		},
		version.SchemeRPM: {
			{"1.0-1.el8", "1.0-2.el8"}, {"1.9-1", "1.10-1"}, {"2.0-1", "1:1.0-1"}, {"1.0~rc1-1", "1.0-1"},
		},
		version.SchemeAlpine: {
			{"1.2.3-r0", "1.2.3-r1"}, {"1.2.9-r0", "1.2.10-r0"}, {"1.2.3_rc1-r0", "1.2.3-r0"},
		},
		version.SchemeSemver: {
			{"1.2.3", "1.10.0"}, {"v1.2", "v1.3"}, {"1.0.0-alpha", "1.0.0"},
		},
	}
	c := New()
	for scheme, pairs := range cases {
		for _, p := range pairs {
			if n, err := c.Compare(scheme, p[0], p[1]); err != nil || n != -1 {
				t.Errorf("%s : %s ? %s = %d, %v ; attendu -1", scheme, p[0], p[1], n, err)
			}
			if n, err := c.Compare(scheme, p[1], p[0]); err != nil || n != 1 {
				t.Errorf("%s : %s ? %s = %d, %v ; attendu 1", scheme, p[1], p[0], n, err)
			}
			if n, err := c.Compare(scheme, p[0], p[0]); err != nil || n != 0 {
				t.Errorf("%s : %s ? %s = %d, %v ; attendu 0", scheme, p[0], p[0], n, err)
			}
		}
	}
}

// TestUnreadableVersionsAreReported : une version illisible selon sa règle donne
// ErrNotComparable, jamais un ordre arbitraire.
func TestUnreadableVersionsAreReported(t *testing.T) {
	c := New()
	cases := []struct {
		scheme version.Scheme
		v      string
	}{
		{version.SchemeNPM, "latest"}, {version.SchemeNPM, ""}, {version.SchemePyPI, "not a version"},
		{version.SchemeDebian, "a:1.0"}, {version.SchemeGolang, "devel"}, {version.Scheme("cobol"), "1.0"},
		{version.SchemeRPM, ""},
	}
	for _, k := range cases {
		if _, err := c.Compare(k.scheme, k.v, "1.0.0"); !errors.Is(err, version.ErrNotComparable) {
			t.Errorf("%s %q : %v", k.scheme, k.v, err)
		}
		if _, err := c.Compare(k.scheme, "1.0.0", k.v); !errors.Is(err, version.ErrNotComparable) {
			t.Errorf("%s %q (à droite) : %v", k.scheme, k.v, err)
		}
	}
	for _, s := range version.Schemes() {
		if _, ok := formats[s]; !ok {
			t.Errorf("règle %s sans format de Grype", s)
		}
	}
}
