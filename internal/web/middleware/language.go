package middleware

import (
	"net/http"

	"golang.org/x/text/language"

	"leblanc.io/open-go-base/i18n"

	"leblanc.io/lotor/internal/locale"
)

// LanguageSources fournit les préférences qui ne viennent pas de la requête elle-même :
// la préférence du compte (T03) et la langue de l'organisation. Une source nil ou vide est
// ignorée.
type LanguageSources struct {
	Account func(*http.Request) string
	Org     func(*http.Request) string
}

// Language choisit la langue de la requête dans l'ordre du § 18 (?lang=, compte,
// Accept-Language, organisation, défaut), place le localiseur dans le contexte et
// annonce la langue par Content-Language.
func Language(cat *locale.Catalog, src LanguageSources) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tag := ResolveLanguage(cat, r, src)
			w.Header().Set("Content-Language", tag.String())
			w.Header().Add("Vary", "Accept-Language")
			next.ServeHTTP(w, r.WithContext(locale.NewContext(r.Context(), cat.Localizer(tag))))
		})
	}
}

// ResolveLanguage applique l'ordre du § 18 à une requête.
func ResolveLanguage(cat *locale.Catalog, r *http.Request, src LanguageSources) language.Tag {
	call := func(f func(*http.Request) string) string {
		if f == nil {
			return ""
		}
		return f(r)
	}
	return cat.Resolve(
		r.URL.Query().Get(i18n.QueryParam),
		call(src.Account),
		r.Header.Get("Accept-Language"),
		call(src.Org),
	)
}

// Localizer renvoie le localiseur de la requête : celui de Language s'il a tourné, sinon
// celui que donnent ?lang= et Accept-Language (réponses produites avant Language, comme
// le refus d'une limitation de débit).
func Localizer(cat *locale.Catalog, r *http.Request) *i18n.Localizer {
	if l, ok := locale.FromContext(r.Context()); ok {
		return l
	}
	return cat.Localizer(ResolveLanguage(cat, r, LanguageSources{}))
}
