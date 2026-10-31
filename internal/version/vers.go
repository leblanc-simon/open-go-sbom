package version

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bornes d'une plage vers.
const (
	MaxVersLen         = 1024
	MaxVersConstraints = 64
)

// Erreurs de lecture d'une plage vers.
var (
	// ErrVersSyntax : la plage n'a pas la forme vers:<schéma>/<contraintes>.
	ErrVersSyntax = errors.New("version: plage vers mal formée")
	// ErrVersScheme : schéma vers inconnu.
	ErrVersScheme = errors.New("version: schéma vers inconnu")
	// ErrVersDuplicate : une même version figure dans deux contraintes.
	ErrVersDuplicate = errors.New("version: version répétée dans une plage vers")
	// ErrVersVersion : une version de la plage ne se lit pas selon son schéma.
	ErrVersVersion = errors.New("version: version illisible dans une plage vers")
)

// Op est le comparateur d'une contrainte vers.
type Op string

// Comparateurs de la spécification vers.
const (
	OpEQ Op = "="
	OpNE Op = "!="
	OpLT Op = "<"
	OpLE Op = "<="
	OpGT Op = ">"
	OpGE Op = ">="
)

// Constraint est une contrainte d'une plage : comparateur et version.
type Constraint struct {
	Op      Op
	Version string
}

// Range est une plage de versions au format vers (spécification purl
// VERSION-RANGE-SPEC). Construite par ParseVers, elle est triée et vérifiée selon son
// schéma : ses versions se lisent, chacune n'y figure qu'une fois.
type Range struct {
	// Name est le schéma tel qu'écrit (« npm », « debian »…), Scheme sa règle.
	Name        string
	Scheme      Scheme
	Any         bool // « * » : toutes les versions
	Constraints []Constraint
}

// ParseVers lit une plage vers et la normalise avec le comparateur c : contraintes triées
// par version croissante, versions lisibles selon le schéma et uniques. Les espaces ne
// comptent pas ; une contrainte sans comparateur est une égalité ; les versions sont
// décodées de leur encodage pour cent.
func ParseVers(raw string, c Comparer) (Range, error) {
	r, err := parseVersSyntax(raw)
	if err != nil {
		return Range{}, err
	}
	if r.Any {
		return r, nil
	}
	for _, k := range r.Constraints {
		if !Valid(c, r.Scheme, k.Version) {
			return Range{}, fmt.Errorf("%w : %q", ErrVersVersion, k.Version)
		}
	}
	var dup bool
	slices.SortStableFunc(r.Constraints, func(a, b Constraint) int {
		n, _ := c.Compare(r.Scheme, a.Version, b.Version)
		if n == 0 {
			dup = true
		}
		return n
	})
	if dup {
		return Range{}, ErrVersDuplicate
	}
	return r, nil
}

// parseVersSyntax lit la forme d'une plage, sans comparer ses versions.
func parseVersSyntax(raw string) (Range, error) {
	if len(raw) > MaxVersLen || !utf8.ValidString(raw) {
		return Range{}, ErrVersSyntax
	}
	s := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)
	rest, ok := strings.CutPrefix(s, "vers:")
	if !ok {
		return Range{}, ErrVersSyntax
	}
	name, body, ok := strings.Cut(rest, "/")
	if !ok || name == "" || body == "" {
		return Range{}, ErrVersSyntax
	}
	if name != strings.ToLower(name) {
		return Range{}, ErrVersSyntax
	}
	scheme, ok := ForVers(name)
	if !ok {
		return Range{}, fmt.Errorf("%w : %q", ErrVersScheme, name)
	}
	r := Range{Name: name, Scheme: scheme}
	if body == "*" {
		r.Any = true
		return r, nil
	}
	parts := strings.Split(body, "|")
	if len(parts) > MaxVersConstraints {
		return Range{}, ErrVersSyntax
	}
	for _, p := range parts {
		k, err := parseConstraint(p)
		if err != nil {
			return Range{}, err
		}
		r.Constraints = append(r.Constraints, k)
	}
	return r, nil
}

func parseConstraint(p string) (Constraint, error) {
	var op Op
	switch {
	case strings.HasPrefix(p, ">="), strings.HasPrefix(p, "<="), strings.HasPrefix(p, "!="):
		op, p = Op(p[:2]), p[2:]
	case strings.HasPrefix(p, ">"), strings.HasPrefix(p, "<"), strings.HasPrefix(p, "="):
		op, p = Op(p[:1]), p[1:]
	default:
		op = OpEQ
	}
	v, err := url.PathUnescape(p)
	if err != nil || v == "" || v == "*" || strings.ContainsAny(v, "<>=!|") || strings.ContainsFunc(v, unicode.IsControl) {
		return Constraint{}, ErrVersSyntax
	}
	return Constraint{Op: op, Version: v}, nil
}

// String écrit la plage sous sa forme normale (égalité sans comparateur, versions
// encodées pour cent si besoin).
func (r Range) String() string {
	if r.Any {
		return "vers:" + r.Name + "/*"
	}
	parts := make([]string, len(r.Constraints))
	for i, k := range r.Constraints {
		op := string(k.Op)
		if k.Op == OpEQ {
			op = ""
		}
		parts[i] = op + url.PathEscape(k.Version)
	}
	return "vers:" + r.Name + "/" + strings.Join(parts, "|")
}

// Contains indique si la version v appartient à la plage, selon l'algorithme de la
// spécification vers : égalité d'abord (=, <=, >= l'incluent, != l'exclut), puis les
// intervalles formés par les contraintes d'ordre. Une version illisible selon le schéma
// renvoie une erreur enveloppant ErrNotComparable : l'appelant la signale.
func (r Range) Contains(c Comparer, v string) (bool, error) {
	if r.Any {
		return true, nil
	}
	if !Valid(c, r.Scheme, v) {
		return false, fmt.Errorf("%w : %q", ErrNotComparable, v)
	}
	var ordered []Constraint
	hasNE := false
	for _, k := range r.Constraints {
		n, err := c.Compare(r.Scheme, v, k.Version)
		if err != nil {
			return false, err
		}
		if n == 0 {
			switch k.Op {
			case OpEQ, OpLE, OpGE:
				return true, nil
			case OpNE:
				return false, nil
			}
		}
		switch k.Op {
		case OpNE:
			hasNE = true
		case OpEQ:
		default:
			ordered = append(ordered, k)
		}
	}
	if len(ordered) == 0 {
		// Seulement des égalités et des exclusions : v n'est égale à aucune, elle est donc
		// dans la plage si la plage exclut au lieu d'énumérer.
		return hasNE, nil
	}
	below := func(k Constraint) bool { return k.Op == OpLT || k.Op == OpLE }
	cmpTo := func(k Constraint) int { n, _ := c.Compare(r.Scheme, v, k.Version); return n }
	for i, k := range ordered {
		if i == 0 && below(k) && cmpTo(k) < 0 {
			return true, nil
		}
		if i == len(ordered)-1 && !below(k) && cmpTo(k) > 0 {
			return true, nil
		}
		if i+1 < len(ordered) {
			next := ordered[i+1]
			if !below(k) && below(next) && cmpTo(k) > 0 && cmpTo(next) < 0 {
				return true, nil
			}
		}
	}
	return false, nil
}
