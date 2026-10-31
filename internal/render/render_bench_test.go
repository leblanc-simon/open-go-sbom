package render

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/text/language"
)

// Mesures de l'ADR 0009 : rendu de la page d'accueil avec un jeu de gabarits par langue
// préparé au démarrage (retenu), et avec un clonage par requête d'un jeu jamais exécuté
// (écarté).

func BenchmarkRenderPerLanguageSet(b *testing.B) {
	r := newRenderer(b)
	req := httptest.NewRequest(http.MethodGet, "/?lang=en", nil)
	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		r.Render(rec, req, http.StatusOK, "home/index", &testView{Page{TitleKey: "home.title"}})
	}
}

func BenchmarkRenderCloneEachRequest(b *testing.B) {
	tpl, st := realFS(b)
	assets, err := NewAssets(st)
	if err != nil {
		b.Fatal(err)
	}
	base, err := template.New("").Funcs(staticFuncs(assets)).Funcs(placeholderFuncs()).
		ParseFS(tpl, "layout.html", "partials/*.html", "home/index.html")
	if err != nil {
		b.Fatal(err)
	}
	loc := catalog(b).Localizer(language.English)
	v := &testView{Page{TitleKey: "home.title", Lang: "en"}}
	b.ReportAllocs()
	for b.Loop() {
		t, err := base.Clone()
		if err != nil {
			b.Fatal(err)
		}
		if err := t.Funcs(languageFuncs(loc)).ExecuteTemplate(io.Discard, "layout", v); err != nil {
			b.Fatal(err)
		}
	}
}
