package web

import (
	"net/http"

	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
)

// pathSiteMap est le plan du site, lié depuis le pied de chaque page authentifiée.
const pathSiteMap = "/sitemap"

// siteMapSection est une rubrique du plan : un titre et les pages de la navigation
// latérale correspondante.
type siteMapSection struct {
	ID       string
	TitleKey string
	Title    string // nom d'une organisation, à la place de TitleKey
	Items    []render.NavItem
}

type siteMapView struct {
	render.Page
	Sections []siteMapSection
}

// siteMap est le second système de navigation (RGAA 12.1) : toutes les rubriques
// accessibles au compte, construites par les mêmes fonctions que les navigations
// latérales (compte, chaque organisation selon son rôle, administration de l'instance).
func (id *identity) siteMap(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r)
	view := &siteMapView{Page: render.Page{TitleKey: "sitemap.title"}}
	for _, o := range v.state.Orgs {
		view.Sections = append(view.Sections, siteMapSection{ID: "sitemap-org-" + o.Slug, Title: o.Name,
			Items: orgNav(tenant.Access{Org: o.Org, Slug: o.Slug, Name: o.Name, Role: o.Role}, "")})
	}
	view.Sections = append(view.Sections, siteMapSection{ID: "sitemap-account", TitleKey: "sitemap.account", Items: accountNav("")})
	if v.admin() {
		view.Sections = append(view.Sections, siteMapSection{ID: "sitemap-admin", TitleKey: "sitemap.admin", Items: adminNav("")})
	}
	id.rd.Render(w, r, http.StatusOK, "sitemap/index", view)
}
