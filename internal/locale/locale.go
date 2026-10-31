package locale

import (
	"context"
	"fmt"
	"io/fs"
	"slices"

	"golang.org/x/text/language"

	"leblanc.io/open-go-base/i18n"
)

// maxPreferenceLen borne une préférence analysée (un en-tête Accept-Language reçu).
const maxPreferenceLen = 512

// Catalog regroupe les traductions et un localiseur par langue disponible. Sûr en
// concurrence ; construit une fois au démarrage.
type Catalog struct {
	def        language.Tag
	languages  []language.Tag
	matcher    language.Matcher
	localizers map[language.Tag]*i18n.Localizer
}

// New charge les fichiers YAML de dir dans fsys (un par langue, nommé d'après son
// étiquette BCP 47). defaultLang doit être l'une des langues chargées.
func New(fsys fs.FS, dir, defaultLang string) (*Catalog, error) {
	def, err := language.Parse(defaultLang)
	if err != nil {
		return nil, fmt.Errorf("locale: langue par défaut invalide %q", defaultLang)
	}
	bundle, err := i18n.NewFS(fsys, dir, def.String())
	if err != nil {
		return nil, fmt.Errorf("locale: %w", err)
	}
	c := &Catalog{def: def, localizers: map[language.Tag]*i18n.Localizer{}}
	files, err := fs.Glob(fsys, pathJoin(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("locale: %w", err)
	}
	for _, f := range files {
		name := f[len(pathJoin(dir, "")):]
		tag, err := language.Parse(name[:len(name)-len(".yaml")])
		if err != nil {
			return nil, fmt.Errorf("locale: fichier %s : étiquette de langue invalide", f)
		}
		c.languages = append(c.languages, tag)
	}
	if !slices.Contains(c.languages, def) {
		return nil, fmt.Errorf("locale: la langue par défaut %q n'a pas de traductions (disponibles : %v)", def, c.languages)
	}
	// La langue par défaut d'abord : le matcher s'en sert comme repli.
	slices.SortStableFunc(c.languages, func(a, b language.Tag) int {
		switch {
		case a == def:
			return -1
		case b == def:
			return 1
		default:
			return 0
		}
	})
	c.matcher = language.NewMatcher(c.languages)
	for _, tag := range c.languages {
		c.localizers[tag] = bundle.Localizer(tag.String(), "")
	}
	return c, nil
}

func pathJoin(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return dir + "/" + name
}

// Default renvoie la langue par défaut de l'instance.
func (c *Catalog) Default() language.Tag { return c.def }

// Languages renvoie les langues disponibles, la langue par défaut en premier.
func (c *Catalog) Languages() []language.Tag { return slices.Clone(c.languages) }

// Match renvoie la langue disponible la plus proche d'une préférence : une étiquette
// (« fr-CA ») ou une liste Accept-Language (« de;q=0.9, en;q=0.8 »). ok est faux si rien
// ne correspond.
func (c *Catalog) Match(pref string) (tag language.Tag, ok bool) {
	if pref == "" || len(pref) > maxPreferenceLen {
		return c.def, false
	}
	prefs, _, err := language.ParseAcceptLanguage(pref)
	if err != nil || len(prefs) == 0 {
		return c.def, false
	}
	_, idx, conf := c.matcher.Match(prefs...)
	if conf == language.No {
		return c.def, false
	}
	return c.languages[idx], true
}

// Resolve renvoie la langue de la première préférence prise en charge, dans l'ordre
// donné, ou la langue par défaut.
func (c *Catalog) Resolve(prefs ...string) language.Tag {
	for _, p := range prefs {
		if tag, ok := c.Match(p); ok {
			return tag
		}
	}
	return c.def
}

// Localizer renvoie le localiseur d'une langue disponible ; une autre langue retombe sur
// la langue par défaut.
func (c *Catalog) Localizer(tag language.Tag) *i18n.Localizer {
	if l, ok := c.localizers[tag]; ok {
		return l
	}
	return c.localizers[c.def]
}

type ctxKey struct{}

// NewContext renvoie un contexte qui porte le localiseur de la requête.
func NewContext(ctx context.Context, l *i18n.Localizer) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext renvoie le localiseur de la requête, s'il a été posé.
func FromContext(ctx context.Context) (*i18n.Localizer, bool) {
	l, ok := ctx.Value(ctxKey{}).(*i18n.Localizer)
	return l, ok && l != nil
}
