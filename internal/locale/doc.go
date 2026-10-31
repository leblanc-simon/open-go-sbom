// Package locale charge les traductions embarquées et choisit la langue d'une requête ou
// d'un traitement, selon l'ordre du § 18 de l'architecture : paramètre ?lang=, préférence
// du compte (T03), Accept-Language, langue de l'organisation, langue par défaut de
// l'instance.
//
//	cat, err := locale.New(locales.FS, ".", cfg.I18n.DefaultLanguage)
//	tag := cat.Resolve(r.URL.Query().Get("lang"), accountLang, r.Header.Get("Accept-Language"), orgLang)
//	loc := cat.Localizer(tag)
//	loc.T("home.title")
//
// Chaque préférence vide ou non prise en charge est ignorée ; Resolve renvoie toujours une
// langue disponible. Les localiseurs sont construits une fois par langue et partagés : les
// textes émis hors requête (notifications) utilisent Localizer(orgLang) de la même façon.
//
// Le paquet ne dépend pas de net/http : le middleware de langue vit dans internal/web, qui
// place le localiseur dans le contexte avec NewContext.
package locale
