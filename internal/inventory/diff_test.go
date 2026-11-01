package inventory

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/version/grypeversion"
)

func item(purlType, ns, name, v, qualifiers string) sideItem {
	base := "pkg:" + purlType + "/" + ns + name
	purl := base + "@" + v + qualifiers
	return sideItem{ID: uuid.NewSHA1(uuid.Nil, []byte(purl)), PURL: purl, PURLBase: base, Type: purlType, Name: name, Version: v}
}

// summary décrit un changement en une ligne : nature, purl_base, anciennes et nouvelles
// versions, approximation.
func summary(cs []Change) []string {
	var out []string
	for _, c := range cs {
		o, n := "-", "-"
		if c.Old != nil {
			o = c.Old.Version
		}
		if c.New != nil {
			n = c.New.Version
		}
		s := fmt.Sprintf("%s %s %s→%s", c.Kind, c.PURLBase, o, n)
		if c.Approximate {
			s += " ~"
		}
		out = append(out, s)
	}
	return out
}

// TestClassifyFourKinds : les quatre natures de changement sur un jeu construit à la main
// (critère d'acceptation de T17), dont une montée et une descente que l'ordre des
// chaînes donnerait à l'envers.
func TestClassifyFourKinds(t *testing.T) {
	cmp := grypeversion.New()
	removed := []sideItem{
		item("npm", "", "lodash", "4.17.9", ""),           // monte en 4.17.21 (« 4.17.9 » > « 4.17.21 » en chaîne)
		item("deb", "debian/", "openssl", "3.0.11-1", ""), // descend en 3.0.9-1
		item("pypi", "", "requests", "2.31.0", ""),        // retiré
		item("maven", "org.example/", "lib", "1.0.0", ""), // retiré
	}
	added := []sideItem{
		item("npm", "", "lodash", "4.17.21", ""),
		item("deb", "debian/", "openssl", "3.0.9-1", ""),
		item("golang", "github.com/acme/", "tool", "v1.2.3", ""), // ajouté
	}
	got := summary(classify(cmp, removed, added))
	want := []string{
		"added pkg:golang/github.com/acme/tool -→v1.2.3",
		"removed pkg:maven/org.example/lib 1.0.0→-",
		"removed pkg:pypi/requests 2.31.0→-",
		"upgraded pkg:npm/lodash 4.17.9→4.17.21",
		"downgraded pkg:deb/debian/openssl 3.0.11-1→3.0.9-1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("changements :\n%q\nattendu :\n%q", got, want)
	}
}

// TestClassifySameBaseIsNotAddPlusRemove : deux versions d'un même purl_base forment une
// montée, jamais un ajout plus un retrait ; au-delà des couples, le reste est ajout ou
// retrait.
func TestClassifySameBaseIsNotAddPlusRemove(t *testing.T) {
	cmp := grypeversion.New()
	cases := []struct {
		name           string
		removed, added []sideItem
		want           []string
	}{
		{"une version de chaque côté",
			[]sideItem{item("npm", "", "a", "1.0.0", "")}, []sideItem{item("npm", "", "a", "2.0.0", "")},
			[]string{"upgraded pkg:npm/a 1.0.0→2.0.0"}},
		{"deux versions retirées, une ajoutée : couples dans l'ordre",
			[]sideItem{item("npm", "", "a", "1.0.0", ""), item("npm", "", "a", "3.0.0", "")},
			[]sideItem{item("npm", "", "a", "2.0.0", "")},
			[]string{"removed pkg:npm/a 3.0.0→-", "upgraded pkg:npm/a 1.0.0→2.0.0"}},
		{"même version, autres qualificatifs : retrait et ajout",
			[]sideItem{item("deb", "debian/", "libc6", "2.36-9", "?arch=amd64")},
			[]sideItem{item("deb", "debian/", "libc6", "2.36-9", "?arch=arm64")},
			[]string{"added pkg:deb/debian/libc6 -→2.36-9", "removed pkg:deb/debian/libc6 2.36-9→-"}},
		{"versions incomparables : ordre des chaînes, approché",
			[]sideItem{item("npm", "", "b", "zeta", "")}, []sideItem{item("npm", "", "b", "alpha", "")},
			[]string{"downgraded pkg:npm/b zeta→alpha ~"}},
		{"rien de changé", nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := summary(classify(cmp, c.removed, c.added)); !slices.Equal(got, c.want) {
				t.Fatalf("%q, attendu %q", got, c.want)
			}
		})
	}
}

// TestClassifyIsOrderIndependent : l'ordre de lecture des composants ne change pas le
// résultat.
func TestClassifyIsOrderIndependent(t *testing.T) {
	cmp := grypeversion.New()
	removed := []sideItem{item("npm", "", "a", "1.0.0", ""), item("npm", "", "a", "1.5.0", ""), item("npm", "", "c", "1.0.0", "")}
	added := []sideItem{item("npm", "", "a", "2.0.0", ""), item("npm", "", "a", "0.9.0", ""), item("npm", "", "d", "1.0.0", "")}
	want := summary(classify(cmp, removed, added))
	slices.Reverse(removed)
	slices.Reverse(added)
	if got := summary(classify(cmp, removed, added)); !slices.Equal(got, want) {
		t.Fatalf("%q, attendu %q", got, want)
	}
	counts := countChanges(classify(cmp, removed, added))
	if counts != (DiffCounts{Added: 1, Removed: 1, Upgraded: 1, Downgraded: 1}) || counts.Total() != 4 {
		t.Fatalf("comptes %+v", counts)
	}
}

func TestChangeCursorOrder(t *testing.T) {
	a := Change{Kind: ChangeAdded, PURLBase: "pkg:npm/z", New: &ChangeSide{PURL: "pkg:npm/z@1"}}
	b := Change{Kind: ChangeRemoved, PURLBase: "pkg:npm/a", Old: &ChangeSide{PURL: "pkg:npm/a@1"}}
	if compareChanges(a, b) >= 0 || !cursorOf(a).before(b) || cursorOf(b).before(a) || cursorOf(a).before(a) {
		t.Fatal("ordre des changements : nature d'abord, puis purl_base, curseur strict")
	}
	for _, k := range ChangeKinds() {
		if !k.Valid() {
			t.Fatalf("%s invalide", k)
		}
	}
	if ChangeKind("moved").Valid() {
		t.Fatal("nature inconnue acceptée")
	}
}
