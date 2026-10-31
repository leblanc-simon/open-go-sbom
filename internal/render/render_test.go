package render

import (
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/text/language"

	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/web/webtest"
	"leblanc.io/open-go-sbom/locales"
	"leblanc.io/open-go-sbom/web"
)

func catalog(t testing.TB) *locale.Catalog {
	t.Helper()
	c, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func realFS(t testing.TB) (templates, static fs.FS) {
	t.Helper()
	tpl, err := web.Templates()
	if err != nil {
		t.Fatal(err)
	}
	st, err := web.Static()
	if err != nil {
		t.Fatal(err)
	}
	return tpl, st
}

func newRenderer(t testing.TB) *Renderer {
	t.Helper()
	tpl, st := realFS(t)
	assets, err := NewAssets(st)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Options{Templates: tpl, Assets: assets, Catalog: catalog(t), Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// testView a les champs de la page d'accueil (home/index), rendue par ces tests.
type testView struct {
	Page
	NoOrg bool
	Admin bool
}

func render(t *testing.T, r *Renderer, req *http.Request, name string, v View) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Render(rec, req, http.StatusOK, name, v)
	return rec
}

func TestRenderHomeInEveryLanguage(t *testing.T) {
	r := newRenderer(t)
	cases := map[string]struct {
		query, accept, lang, heading string
	}{
		"défaut":          {"", "", "fr", "Bienvenue sur open-go-sbom"},
		"Accept-Language": {"", "en-US,en;q=0.9", "en", "Welcome to open-go-sbom"},
		"?lang=":          {"?lang=en", "fr", "en", "Welcome to open-go-sbom"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/"+c.query, nil)
			req.Header.Set("Accept-Language", c.accept)
			rec := render(t, r, req, "home/index", &testView{Page: Page{TitleKey: "home.title"}})
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, `lang="`+c.lang+`"`) || !strings.Contains(body, c.heading) {
				t.Fatalf("statut %d, corps :\n%s", rec.Code, body)
			}
			if !strings.Contains(body, "1.2.3") {
				t.Error("version absente du pied de page")
			}
			if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q", got)
			}
			webtest.AssertAccessible(t, rec.Body.Bytes())
			webtest.AssertNoInlineCode(t, rec.Body.Bytes())
		})
	}
}

func TestRenderTheme(t *testing.T) {
	r := newRenderer(t)
	for cookie, want := range map[string]string{"dark": `data-theme="dark"`, "light": `data-theme="light"`, "evil": "", "": ""} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: ThemeCookie, Value: cookie})
		}
		body := render(t, r, req, "home/index", &testView{Page: Page{TitleKey: "home.title"}}).Body.String()
		has := strings.Contains(body, "data-theme=")
		if want == "" && has || want != "" && !strings.Contains(body, want) {
			t.Errorf("cookie %q : data-theme incorrect", cookie)
		}
	}
}

func TestRenderNavigation(t *testing.T) {
	r := newRenderer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	v := &testView{Page: Page{TitleKey: "home.title", Nav: []NavItem{
		{LabelKey: "home.title", Href: "/", Current: true},
		{LabelKey: "error.back_home", Href: "/x"},
	}}}
	rec := render(t, r, req, "home/index", v)
	body := rec.Body.String()
	if !strings.Contains(body, `<nav class="sidenav" aria-label="Navigation principale">`) ||
		!strings.Contains(body, `href="/" aria-current="page"`) || strings.Count(body, "aria-current") != 1 {
		t.Fatalf("navigation incorrecte :\n%s", body)
	}
	webtest.AssertAccessible(t, rec.Body.Bytes())
	without := render(t, r, req, "home/index", &testView{Page: Page{TitleKey: "home.title"}}).Body.String()
	if strings.Contains(without, "sidenav") {
		t.Fatal("navigation vide affichée")
	}
}

func TestErrorPages(t *testing.T) {
	r := newRenderer(t)
	for _, status := range ErrorStatuses() {
		for _, lang := range []string{"fr", "en"} {
			req := httptest.NewRequest(http.MethodGet, "/x?lang="+lang, nil)
			rec := httptest.NewRecorder()
			r.Error(rec, req, status)
			body := rec.Body.String()
			if rec.Code != status {
				t.Errorf("%d/%s : statut %d", status, lang, rec.Code)
			}
			// Une clé non traduite s'afficherait telle quelle.
			if strings.Contains(body, ErrorKey(status)) {
				t.Errorf("%d/%s : clé non traduite dans la page", status, lang)
			}
			webtest.AssertAccessible(t, rec.Body.Bytes())
			webtest.AssertNoInlineCode(t, rec.Body.Bytes())
		}
	}
	if ErrorKey(http.StatusTeapot) != "error.internal" {
		t.Error("statut sans page dédiée : error.internal attendu")
	}
}

func TestRenderFailureGivesErrorPage(t *testing.T) {
	r := newRenderer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.Render(rec, req, http.StatusOK, "absente/page", &testView{Page: Page{TitleKey: "home.title"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Erreur interne") {
		t.Fatalf("page inconnue : %d\n%s", rec.Code, rec.Body.String())
	}
	// Une erreur d'exécution donne aussi la page 500, sans corps partiel.
	_, st := realFS(t)
	assets, err := NewAssets(st)
	if err != nil {
		t.Fatal(err)
	}
	tpl := fstest.MapFS{
		"layout.html":       {Data: []byte(`{{define "layout"}}<p>{{T "app.name"}}</p>{{template "content" .}}{{end}}`)},
		"errors/error.html": {Data: []byte(`{{define "content"}}{{T .Page.TitleKey}}{{end}}`)},
		"broken/page.html":  {Data: []byte(`{{define "content"}}{{T "home.title" "impair"}}{{end}}`)},
	}
	broken, err := New(Options{Templates: tpl, Assets: assets, Catalog: catalog(t)})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	broken.Render(rec, req, http.StatusOK, "broken/page", &testView{Page: Page{TitleKey: "home.title"}})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "Accueil") ||
		!strings.Contains(rec.Body.String(), "Erreur interne") {
		t.Fatalf("erreur d'exécution : %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestNewRejectsInvalidTemplates(t *testing.T) {
	_, st := realFS(t)
	assets, err := NewAssets(st)
	if err != nil {
		t.Fatal(err)
	}
	layout := `{{define "layout"}}<html lang="{{.Page.Lang}}"><title>{{T "app.name"}}</title>{{template "content" .}}</html>{{end}}`
	cases := map[string]fstest.MapFS{
		"syntaxe": {
			"layout.html":       {Data: []byte(layout)},
			"errors/error.html": {Data: []byte(`{{define "content"}}{{if}}{{end}}`)},
		},
		"échappement ambigu": {
			"layout.html":       {Data: []byte(layout)},
			"errors/error.html": {Data: []byte(`{{define "content"}}<a href="{{.Page.Lang}}{{end}}`)},
		},
		"content absent": {
			"layout.html":       {Data: []byte(layout)},
			"errors/error.html": {Data: []byte(`<p>rien</p>`)},
		},
		"fonction inconnue": {
			"layout.html":       {Data: []byte(layout)},
			"errors/error.html": {Data: []byte(`{{define "content"}}{{nope}}{{end}}`)},
		},
		"page d'erreur absente": {
			"layout.html":     {Data: []byte(layout)},
			"home/index.html": {Data: []byte(`{{define "content"}}x{{end}}`)},
		},
		"layout absent": {
			"errors/error.html": {Data: []byte(`{{define "content"}}x{{end}}`)},
		},
	}
	for name, tpl := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Options{Templates: tpl, Assets: assets, Catalog: catalog(t)}); err == nil {
				t.Fatal("gabarits invalides acceptés")
			}
		})
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("options vides acceptées")
	}
}

func TestTemplateData(t *testing.T) {
	cases := []struct {
		args    []any
		want    map[string]any
		wantErr bool
	}{
		{nil, nil, false},
		{[]any{nil}, nil, false},
		{[]any{map[string]any{}}, nil, false},
		{[]any{map[string]any{"A": 1}}, map[string]any{"A": 1}, false},
		{[]any{"A", 1, "B", "x"}, map[string]any{"A": 1, "B": "x"}, false},
		{[]any{"A"}, nil, true},
		{[]any{"A", 1, "B"}, nil, true},
		{[]any{1, 2}, nil, true},
	}
	for _, c := range cases {
		got, err := templateData(c.args)
		if (err != nil) != c.wantErr || len(got) != len(c.want) {
			t.Errorf("templateData(%v) = %v, %v", c.args, got, err)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("templateData(%v)[%s] = %v", c.args, k, got[k])
			}
		}
	}
}

func TestLanguageFuncs(t *testing.T) {
	f := languageFuncs(catalog(t).Localizer(language.English))
	tr := f["T"].(func(string, ...any) (string, error))
	if s, err := tr("footer.version", "Version", "9"); err != nil || s != "Version 9" {
		t.Fatalf("T = %q, %v", s, err)
	}
	if _, err := tr("footer.version", "Version"); err == nil {
		t.Fatal("paires impaires acceptées")
	}
	tn := f["Tn"].(func(string, int, ...any) (string, error))
	if s, err := tn("home.title", 2); err != nil || s == "" {
		t.Fatalf("Tn = %q, %v", s, err)
	}
	if s, err := tn("home.title", 2, "X", 1); err != nil || s == "" {
		t.Fatalf("Tn avec paramètres = %q, %v", s, err)
	}
	if _, err := tn("home.title", 2, "X"); err == nil {
		t.Fatal("Tn : paires impaires acceptées")
	}
	fr := languageFuncs(catalog(t).Localizer(language.French))
	for _, c := range []struct {
		funcs  template.FuncMap
		name   string
		v      float64
		digits int
		want   string
	}{
		{f, "decimal", 9.75, 1, "9.8"}, {fr, "decimal", 10, 1, "10,0"},
		{f, "percent", 0.944, 1, "94.4%"}, {fr, "percent", 0.944, 1, "94,4 %"},
	} {
		if got := c.funcs[c.name].(func(float64, int) string)(c.v, c.digits); got != c.want {
			t.Errorf("%s(%v) = %q, attendu %q", c.name, c.v, got, c.want)
		}
	}
	field := staticFuncs(&Assets{})["csrfField"].(func(string) template.HTML)
	if got := field(`a"<b`); got != `<input type="hidden" name="csrf_token" value="a&#34;&lt;b">` {
		t.Fatalf("csrfField = %s", got)
	}
}

// keyUse repère les clés littérales passées à T et Tn.
var keyUse = regexp.MustCompile(`\{\{-?\s*Tn?\s+"([^"]+)"`)

// TestTemplatesUseKnownKeys fait échouer les tests si un gabarit emploie une clé absente
// des traductions.
func TestTemplatesUseKnownKeys(t *testing.T) {
	tpl, _ := realFS(t)
	keys, err := locales.Keys()
	if err != nil {
		t.Fatal(err)
	}
	used := 0
	err = fs.WalkDir(tpl, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(tpl, name)
		if err != nil {
			return err
		}
		for _, m := range keyUse.FindAllStringSubmatch(string(body), -1) {
			used++
			if !slices.Contains(keys, m[1]) {
				t.Errorf("%s : clé %q absente des traductions", name, m[1])
			}
		}
		return nil
	})
	if err != nil || used == 0 {
		t.Fatalf("parcours des gabarits : %d clés, %v", used, err)
	}
	for _, s := range ErrorStatuses() {
		for _, suffix := range []string{".title", ".text"} {
			if !slices.Contains(keys, ErrorKey(s)+suffix) {
				t.Errorf("clé %s%s absente", ErrorKey(s), suffix)
			}
		}
	}
}

var (
	actions    = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	comments   = regexp.MustCompile(`(?s)<!--.*?-->`)
	tags       = regexp.MustCompile(`(?s)<[^>]*>`)
	letters    = regexp.MustCompile(`\p{L}`)
	textAttrs  = regexp.MustCompile(`(?i)\s(aria-label|aria-description|title|placeholder|alt|value|label|data-label-[a-z-]+)="([^"]*)"`)
	svgContent = regexp.MustCompile(`(?s)<svg.*?</svg>`)
)

// TestTemplatesHaveNoHardcodedText : aucun texte visible en dur, ni entre les balises
// ni dans les attributs lus par l'utilisateur ou ses aides techniques.
func TestTemplatesHaveNoHardcodedText(t *testing.T) {
	tpl, _ := realFS(t)
	err := fs.WalkDir(tpl, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(tpl, name)
		if err != nil {
			return err
		}
		// Les actions sont retirées d'abord : leurs guillemets fermeraient les attributs.
		src := actions.ReplaceAllString(svgContent.ReplaceAllString(comments.ReplaceAllString(string(body), ""), ""), "")
		for _, m := range textAttrs.FindAllStringSubmatch(src, -1) {
			if letters.MatchString(m[2]) {
				t.Errorf("%s : attribut %s en dur : %q", name, m[1], m[2])
			}
		}
		visible := tags.ReplaceAllString(src, " ")
		if letters.MatchString(visible) {
			t.Errorf("%s : texte en dur : %q", name, strings.Join(strings.Fields(visible), " "))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRendererIsSafeForConcurrentUse(t *testing.T) {
	r := newRenderer(t)
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for _, lang := range []string{"fr", "en"} {
				req := httptest.NewRequest(http.MethodGet, "/?lang="+lang, nil)
				rec := httptest.NewRecorder()
				r.Render(rec, req, http.StatusOK, "home/index", &testView{Page: Page{TitleKey: "home.title"}})
				_, _ = io.Copy(io.Discard, rec.Body)
			}
		}()
	}
	for range 8 {
		<-done
	}
	if len(r.Pages()) < 2 {
		t.Fatalf("pages = %v", r.Pages())
	}
}
