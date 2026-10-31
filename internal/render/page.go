package render

// Page porte ce que le layout affiche sur toutes les pages. Chaque écran a son modèle de
// vue, qui embarque Page :
//
//	type homeView struct {
//		render.Page
//		Projects []projectRow
//	}
//
// Le handler remplit TitleKey (et éventuellement Nav, Scripts) ; Render remplit le reste
// depuis la requête, si bien qu'aucune page ne peut oublier sa langue ou son jeton CSRF.
type Page struct {
	// TitleKey est la clé de traduction du titre ; TitleArgs ses paramètres.
	TitleKey  string
	TitleArgs map[string]any
	// Nav est la navigation latérale ; vide, elle n'est pas affichée.
	Nav []NavItem
	// Scripts liste les modules JS propres à l'écran (« js/search.js »).
	Scripts []string

	// Remplis par Render.
	Lang      string // étiquette BCP 47 de la page
	Theme     string // "", "light" ou "dark" (cookie de la bascule de thème)
	CSRFToken string // à insérer dans chaque formulaire par {{csrfField .Page.CSRFToken}}
	RequestID string
	Version   string
}

// NavItem est une entrée de la navigation latérale.
type NavItem struct {
	LabelKey string
	Href     string
	Current  bool
}

// View est le modèle de vue d'une page : il embarque Page.
type View interface {
	base() *Page
}

func (p *Page) base() *Page { return p }
