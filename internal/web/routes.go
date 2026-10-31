package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-sbom/internal/render"
)

// registerUI déclare les routes de l'interface. Les écrans des lots suivants s'y ajoutent.
func registerUI(r chi.Router, h *handlers) {
	r.Get("/", h.home)
}

type handlers struct {
	renderer *render.Renderer
}

type homeView struct {
	render.Page
}

func (h *handlers) home(w http.ResponseWriter, r *http.Request) {
	h.renderer.Render(w, r, http.StatusOK, "home/index", &homeView{Page: render.Page{TitleKey: "home.title"}})
}
