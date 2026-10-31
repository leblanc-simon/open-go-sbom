package version_test

import (
	"errors"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/version"
)

// FuzzParseVers : sur toute entrée, l'analyseur ne panique pas ; une plage acceptée se
// réécrit sous une forme normale qui se relit à l'identique, et l'appartenance d'une
// version ne dépend que de la plage (même résultat sur la forme normale).
func FuzzParseVers(f *testing.F) {
	for _, s := range []string{
		"vers:npm/<4.17.21", "vers:npm/>=1.0.0|<2.0.0", "vers:pypi/>=1.0|!=1.5|<2.0", "vers:deb/<1:1.0",
		"vers:npm/*", "vers:maven/1.0|2.0", "vers:golang/>v1.2.0|<=v1.10.0", "vers:semver/1.0.0%2Bbuild", "vers:npm/",
	} {
		f.Add(s, "1.5.0")
	}
	f.Fuzz(func(t *testing.T, raw, v string) {
		r, err := version.ParseVers(raw, cmp)
		if err != nil {
			for _, want := range []error{version.ErrVersSyntax, version.ErrVersScheme, version.ErrVersDuplicate, version.ErrVersVersion} {
				if errors.Is(err, want) {
					return
				}
			}
			t.Fatalf("%q : erreur inattendue %v", raw, err)
		}
		norm := r.String()
		again, err := version.ParseVers(norm, cmp)
		if err != nil || again.String() != norm {
			t.Fatalf("%q → %q → %q, %v", raw, norm, again.String(), err)
		}
		in, err := r.Contains(cmp, v)
		in2, err2 := again.Contains(cmp, v)
		if in != in2 || (err == nil) != (err2 == nil) {
			t.Fatalf("%q et %q divergent sur %q : %v/%v, %v/%v", raw, norm, v, in, in2, err, err2)
		}
		if err != nil && !errors.Is(err, version.ErrNotComparable) && !strings.Contains(err.Error(), "version") {
			t.Fatalf("erreur inattendue %v", err)
		}
	})
}
