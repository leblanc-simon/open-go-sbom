package render

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Chrome est ce que l'en-tête affiche du visiteur connecté : compte, organisations,
// organisation courante. Le middleware d'identité le place dans le contexte ; Render le
// recopie dans Page. Sans lui (visiteur anonyme), l'en-tête ne montre que la marque.
type Chrome struct {
	UserEmail string
	// Authenticated : session complète (pas une session de configuration du TOTP) ;
	// le pied de page lie alors le plan du site.
	Authenticated bool
	Admin         bool       // administrateur d'instance : lien vers l'administration
	Orgs          []OrgEntry // sélecteur d'organisation
	Current       *OrgEntry  // organisation de la page, s'il y en a une
	// Theme est la préférence du compte, utilisée faute de cookie de la bascule.
	Theme string
}

// OrgEntry est une organisation du sélecteur.
type OrgEntry struct {
	Slug    string
	Name    string
	Current bool
}

// Initials renvoie les deux premières initiales d'un nom, pour l'avatar.
func Initials(name string) string {
	var out []rune
	for _, word := range strings.FieldsFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		r, _ := utf8.DecodeRuneInString(word)
		out = append(out, unicode.ToUpper(r))
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

type chromeKey struct{}

// WithChrome renvoie un contexte qui porte l'en-tête du visiteur.
func WithChrome(ctx context.Context, c *Chrome) context.Context {
	return context.WithValue(ctx, chromeKey{}, c)
}

// ChromeFrom renvoie l'en-tête du visiteur, ou nil.
func ChromeFrom(ctx context.Context) *Chrome {
	c, _ := ctx.Value(chromeKey{}).(*Chrome)
	return c
}
