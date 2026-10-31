package grypeversion

import (
	"cmp"
	"fmt"
	"strings"

	grype "github.com/anchore/grype/grype/version"

	"leblanc.io/open-go-sbom/internal/version"
)

// formats associe chaque règle du projet au format de Grype qui l'implémente.
var formats = map[version.Scheme]grype.Format{
	version.SchemeNPM:    grype.SemanticFormat,
	version.SchemeMaven:  grype.MavenFormat,
	version.SchemePyPI:   grype.PythonFormat,
	version.SchemeGem:    grype.GemFormat,
	version.SchemeGolang: grype.GolangFormat,
	version.SchemeDebian: grype.DebFormat,
	version.SchemeRPM:    grype.RpmFormat,
	version.SchemeAlpine: grype.ApkFormat,
	version.SchemeSemver: grype.SemanticFormat,
}

// Comparer compare les versions avec les comparateurs de Grype. Sans état : une valeur
// zéro sert, et elle peut être partagée entre goroutines.
type Comparer struct{}

var _ version.Comparer = Comparer{}

// New renvoie le comparateur.
func New() Comparer { return Comparer{} }

// withEpoch écrit l'époque 0 d'une version rpm qui n'en a pas. Le comparateur rpm de Grype
// ignore une époque présente d'un seul côté (règle de correspondance avec une base de
// vulnérabilités) ; pour ordonner deux versions d'un inventaire, une époque absente vaut 0,
// comme le veut rpm.
func withEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		return v
	}
	return "0:" + v
}

// Compare compare a et b selon la règle s. Une version que le format de Grype ne lit pas,
// ou une règle inconnue, donne une erreur enveloppant version.ErrNotComparable.
func (Comparer) Compare(s version.Scheme, a, b string) (int, error) {
	f, ok := formats[s]
	if !ok {
		return 0, fmt.Errorf("%w : règle %q inconnue", version.ErrNotComparable, s)
	}
	ga, gb := a, b
	if s == version.SchemeRPM {
		ga, gb = withEpoch(a), withEpoch(b)
	}
	va, vb := grype.New(ga, f), grype.New(gb, f)
	if a == "" || va.Validate() != nil {
		return 0, fmt.Errorf("%w : %q (%s)", version.ErrNotComparable, a, s)
	}
	if b == "" || vb.Validate() != nil {
		return 0, fmt.Errorf("%w : %q (%s)", version.ErrNotComparable, b, s)
	}
	ab, err := va.Compare(vb)
	if err != nil {
		return 0, fmt.Errorf("%w : %q et %q (%s)", version.ErrNotComparable, a, b, s)
	}
	ba, err := vb.Compare(va)
	if err != nil {
		return 0, fmt.Errorf("%w : %q et %q (%s)", version.ErrNotComparable, b, a, s)
	}
	// Les comparateurs de Grype servent la correspondance avec une base, pas le tri : dpkg
	// renvoie une différence plutôt qu'un signe, PEP 440 n'est pas antisymétrique sur les
	// versions locales (« 0+00 » et « 0 »). Combiner les deux sens donne un signe
	// antisymétrique, identique au résultat de Grype quand celui-ci l'est déjà.
	return cmp.Compare(cmp.Compare(ab, 0), cmp.Compare(ba, 0)), nil
}
