package version_test

import (
	"errors"
	"slices"
	"testing"

	"leblanc.io/open-go-sbom/internal/version"
	"leblanc.io/open-go-sbom/internal/version/grypeversion"
)

var cmp = grypeversion.New()

func TestForPURLTypeAndVersSchemes(t *testing.T) {
	for typ, want := range map[string]version.Scheme{
		"npm": version.SchemeNPM, "maven": version.SchemeMaven, "pypi": version.SchemePyPI, "gem": version.SchemeGem,
		"golang": version.SchemeGolang, "deb": version.SchemeDebian, "rpm": version.SchemeRPM, "apk": version.SchemeAlpine,
		"cargo": version.SchemeSemver, "generic": version.SchemeSemver, "nuget": version.SchemeSemver,
	} {
		if got := version.ForPURLType(typ); got != want {
			t.Errorf("type %s : %s, attendu %s", typ, got, want)
		}
	}
	for name, want := range map[string]version.Scheme{"debian": version.SchemeDebian, "alpine": version.SchemeAlpine, "cargo": version.SchemeSemver} {
		if got, ok := version.ForVers(name); !ok || got != want {
			t.Errorf("vers %s : %s %v", name, got, ok)
		}
	}
	if _, ok := version.ForVers("cobol"); ok {
		t.Error("schéma inconnu accepté")
	}
}

// TestVersRangeContains : appartenance à une plage selon l'algorithme de la
// spécification vers, versions comparées par l'écosystème.
func TestVersRangeContains(t *testing.T) {
	cases := []struct {
		vers    string
		in, out []string
	}{
		{"vers:npm/<4.17.21", []string{"4.17.20", "4.9.0", "0.1.0", "4.17.21-rc.1"}, []string{"4.17.21", "4.18.0", "10.0.0"}},
		{"vers:npm/>=1.0.0|<2.0.0", []string{"1.0.0", "1.5.3", "1.99.0"}, []string{"0.9.0", "2.0.0", "2.0.1"}},
		{"vers:maven/>=2.0-beta9|<2.15.0", []string{"2.0-beta9", "2.14.1", "2.9.1"}, []string{"2.15.0", "2.17.1", "1.2.17", "2.0-beta8"}},
		{"vers:pypi/>=1.0|!=1.5|<2.0", []string{"1.0", "1.4", "1.6", "1.10"}, []string{"1.5", "2.0", "0.9", "1.0rc1"}},
		{"vers:deb/<1:1.0", []string{"2.0", "1:0.9"}, []string{"1:1.0", "1:2.0"}},
		{"vers:golang/>v1.2.0|<=v1.10.0|>=v2.0.0", []string{"v1.3.0", "v1.10.0", "v2.1.0"}, []string{"v1.2.0", "v1.11.0", "v1.0.0"}},
		{"vers:npm/1.0.0|2.0.0", []string{"1.0.0", "2.0.0"}, []string{"1.5.0", "3.0.0"}},
		{"vers:npm/!=1.0.0", []string{"0.1.0", "2.0.0"}, []string{"1.0.0"}},
		{"vers:npm/*", []string{"0.0.1", "99.0.0"}, nil},
		{"vers:rpm/<=1:1.0-1|>2:0.1-1", []string{"1.0-1", "1:1.0-1", "3:0.1-1"}, []string{"1:1.1-1", "2:0.1-1"}},
	}
	for _, c := range cases {
		r, err := version.ParseVers(c.vers, cmp)
		if err != nil {
			t.Fatalf("%s : %v", c.vers, err)
		}
		for _, v := range c.in {
			if ok, err := r.Contains(cmp, v); err != nil || !ok {
				t.Errorf("%s ∌ %s (%v)", c.vers, v, err)
			}
		}
		for _, v := range c.out {
			if ok, err := r.Contains(cmp, v); err != nil || ok {
				t.Errorf("%s ∋ %s (%v)", c.vers, v, err)
			}
		}
	}
}

// TestVersRangeIsNeverTextual : « 4.9.0 » < « 4.17.21 » selon npm, alors que l'ordre
// lexical dit l'inverse.
func TestVersRangeIsNeverTextual(t *testing.T) {
	r, err := version.ParseVers("vers:npm/<4.17.21", cmp)
	if err != nil {
		t.Fatal(err)
	}
	if "4.9.0" < "4.17.21" {
		t.Fatal("cas mal choisi")
	}
	if ok, _ := r.Contains(cmp, "4.9.0"); !ok {
		t.Fatal("4.9.0 comparée comme du texte")
	}
}

func TestVersNormalizesOrderAndSpaces(t *testing.T) {
	r, err := version.ParseVers(" vers:npm/ <2.0.0 | >=1.0.0 ", cmp)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.String(); got != "vers:npm/>=1.0.0|<2.0.0" {
		t.Fatalf("forme normale %q", got)
	}
	r, err = version.ParseVers("vers:npm/=1.0.0%7Cx", cmp)
	if err == nil {
		t.Fatalf("version illisible acceptée : %v", r)
	}
	r, err = version.ParseVers("vers:semver/1.0.0%2Bbuild", cmp)
	if err != nil || r.Constraints[0].Version != "1.0.0+build" || r.String() != "vers:semver/1.0.0+build" {
		t.Fatalf("décodage pour cent : %+v %v", r, err)
	}
}

func TestVersRejects(t *testing.T) {
	cases := map[string]error{
		"npm/<1.0.0":                       version.ErrVersSyntax,
		"vers:npm":                         version.ErrVersSyntax,
		"vers:npm/":                        version.ErrVersSyntax,
		"vers:/<1.0.0":                     version.ErrVersSyntax,
		"vers:NPM/<1.0.0":                  version.ErrVersSyntax,
		"vers:npm/<":                       version.ErrVersSyntax,
		"vers:npm/<1.0.0||>2.0.0":          version.ErrVersSyntax,
		"vers:npm/*|<1.0.0":                version.ErrVersSyntax,
		"vers:npm/<=>1.0.0":                version.ErrVersSyntax,
		"vers:cobol/<1.0":                  version.ErrVersScheme,
		"vers:npm/<1.0.0|>=1.0.0":          version.ErrVersDuplicate,
		"vers:npm/<latest":                 version.ErrVersVersion,
		"vers:deb/<a:b":                    version.ErrVersVersion,
		"vers:npm/%zz":                     version.ErrVersSyntax,
		"vers:npm/" + string([]byte{0xff}): version.ErrVersSyntax,
	}
	for raw, want := range cases {
		if _, err := version.ParseVers(raw, cmp); !errors.Is(err, want) {
			t.Errorf("%q : %v, attendu %v", raw, err, want)
		}
	}
	long := "vers:npm/"
	for i := range version.MaxVersConstraints + 1 {
		if i > 0 {
			long += "|"
		}
		long += "1.0." + string(rune('0'+i%10))
	}
	if _, err := version.ParseVers(long, cmp); !errors.Is(err, version.ErrVersSyntax) {
		t.Errorf("trop de contraintes : %v", err)
	}
}

// TestUnreadableVersionIsReported : une version de l'inventaire illisible selon son
// écosystème est signalée, jamais classée dans la plage ou hors d'elle en silence.
func TestUnreadableVersionIsReported(t *testing.T) {
	r, err := version.ParseVers("vers:npm/<4.17.21", cmp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Contains(cmp, "latest"); !errors.Is(err, version.ErrNotComparable) {
		t.Fatalf("version illisible : %v", err)
	}
}

// TestSortByEcosystem : la fiche composant trie ses versions par écosystème ; les versions
// illisibles sont à part.
func TestSortByEcosystem(t *testing.T) {
	// Maven lit toute chaîne (un qualificatif seul se classe avant les versions).
	sorted, unreadable := version.Sort(cmp, version.SchemeMaven, []string{"2.17.1", "2.9.1", "2.14.1", "2.9.1", "1.0-alpha", "1.0"})
	if !slices.Equal(sorted, []string{"1.0-alpha", "1.0", "2.9.1", "2.14.1", "2.17.1"}) || len(unreadable) != 0 {
		t.Fatalf("tri maven : %v %v", sorted, unreadable)
	}
	_, unreadable = version.Sort(cmp, version.SchemeNPM, []string{"1.0.0", "latest", "next", "latest"})
	if !slices.Equal(unreadable, []string{"latest", "next"}) {
		t.Fatalf("versions illisibles : %v", unreadable)
	}
}
