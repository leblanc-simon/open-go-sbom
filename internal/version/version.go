package version

import (
	"cmp"
	"errors"
	"slices"
)

// Scheme est une règle de comparaison de versions : celle d'un écosystème, ou le semver
// générique pour les écosystèmes qui s'en rapprochent.
type Scheme string

// Règles de comparaison prises en charge (ADR 0026).
const (
	SchemeNPM    Scheme = "npm"    // node-semver
	SchemeMaven  Scheme = "maven"  // ComparableVersion de Maven
	SchemePyPI   Scheme = "pypi"   // PEP 440
	SchemeGem    Scheme = "gem"    // RubyGems
	SchemeGolang Scheme = "golang" // modules Go (semver, pseudo-versions, +incompatible)
	SchemeDebian Scheme = "deb"    // dpkg (époque, révision, ~)
	SchemeRPM    Scheme = "rpm"    // rpmvercmp (époque, version, publication)
	SchemeAlpine Scheme = "alpine" // apk-tools
	SchemeSemver Scheme = "semver" // semver générique, toléré (« v1.2 », « 1.0a »)
)

// Schemes renvoie toutes les règles, dans un ordre stable.
func Schemes() []Scheme {
	return []Scheme{SchemeNPM, SchemeMaven, SchemePyPI, SchemeGem, SchemeGolang, SchemeDebian, SchemeRPM, SchemeAlpine, SchemeSemver}
}

// purlTypes associe le type d'un purl à sa règle ; tout autre type (cargo, nuget,
// composer, generic…) se compare en semver générique.
var purlTypes = map[string]Scheme{
	"npm": SchemeNPM, "maven": SchemeMaven, "pypi": SchemePyPI, "gem": SchemeGem, "golang": SchemeGolang,
	"deb": SchemeDebian, "rpm": SchemeRPM, "apk": SchemeAlpine,
}

// ForPURLType renvoie la règle de comparaison des versions d'un type de purl.
func ForPURLType(purlType string) Scheme {
	if s, ok := purlTypes[purlType]; ok {
		return s
	}
	return SchemeSemver
}

// versSchemes associe les noms de schéma de la spécification vers à leur règle. Les
// écosystèmes semver (cargo, nuget…) y sont acceptés sous leur propre nom.
var versSchemes = map[string]Scheme{
	"npm": SchemeNPM, "maven": SchemeMaven, "pypi": SchemePyPI, "gem": SchemeGem, "golang": SchemeGolang,
	"deb": SchemeDebian, "debian": SchemeDebian, "rpm": SchemeRPM, "alpine": SchemeAlpine, "apk": SchemeAlpine,
	"semver": SchemeSemver, "generic": SchemeSemver, "cargo": SchemeSemver, "nuget": SchemeSemver,
	"composer": SchemeSemver, "hex": SchemeSemver, "pub": SchemeSemver, "swift": SchemeSemver,
	"conan": SchemeSemver, "cocoapods": SchemeSemver, "hackage": SchemeSemver, "github": SchemeSemver,
}

// ForVers renvoie la règle d'un nom de schéma vers.
func ForVers(name string) (Scheme, bool) {
	s, ok := versSchemes[name]
	return s, ok
}

// ErrNotComparable : une version ne se lit pas selon la règle demandée (« latest », date
// libre, version mal formée). Le comparateur l'enveloppe ; elle n'est jamais ignorée en
// silence par l'appelant.
var ErrNotComparable = errors.New("version: version non comparable")

// Comparer compare deux versions selon une règle : -1, 0 ou 1 si a est inférieure, égale
// ou supérieure à b, ou une erreur enveloppant ErrNotComparable si l'une ne se lit pas.
// L'implémentation de référence est l'adaptateur grypeversion.
type Comparer interface {
	Compare(s Scheme, a, b string) (int, error)
}

// Valid indique si v se lit selon la règle s.
func Valid(c Comparer, s Scheme, v string) bool {
	_, err := c.Compare(s, v, v)
	return err == nil
}

// Sort trie des versions selon la règle s, sans doublon : les versions comparables par
// ordre croissant, puis celles qui ne se lisent pas, par ordre lexical.
func Sort(c Comparer, s Scheme, versions []string) (sorted, unreadable []string) {
	for _, v := range versions {
		if Valid(c, s, v) {
			sorted = append(sorted, v)
		} else {
			unreadable = append(unreadable, v)
		}
	}
	slices.SortStableFunc(sorted, func(a, b string) int {
		r, err := c.Compare(s, a, b)
		if err != nil {
			return cmp.Compare(a, b)
		}
		// Deux écritures d'une même version (« 1.0 » et « 1.0.0 ») gardent un ordre stable.
		return cmp.Or(r, cmp.Compare(a, b))
	})
	slices.Sort(unreadable)
	return slices.Compact(sorted), slices.Compact(unreadable)
}
