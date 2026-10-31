package render

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"

	"golang.org/x/text/language"

	"leblanc.io/open-go-base/csrfx"
	"leblanc.io/open-go-base/i18n"

	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/web/middleware"
)

// ThemeCookie porte le thème choisi par la bascule (web/static/js/theme.js).
const ThemeCookie = "lotor_theme"

// ErrorPage est la page d'erreur.
const ErrorPage = "errors/error"

// Options paramètre New.
type Options struct {
	// Templates contient layout.html, partials/*.html et un dossier par écran.
	Templates fs.FS
	Assets    *Assets
	Catalog   *locale.Catalog
	// Version s'affiche en pied de page.
	Version string
	Logger  *slog.Logger
}

// Renderer rend les pages. Les gabarits sont analysés et échappés au démarrage, un jeu
// par page et par langue (ADR 0009) : un rendu ne clone rien.
type Renderer struct {
	pages   map[language.Tag]map[string]*template.Template
	assets  *Assets
	cat     *locale.Catalog
	version string
	logger  *slog.Logger
	buffers sync.Pool
}

// New analyse tous les gabarits. Un gabarit invalide (syntaxe, contexte d'échappement
// ambigu, gabarit appelé mais absent) empêche le démarrage.
func New(opts Options) (*Renderer, error) {
	if opts.Templates == nil || opts.Assets == nil || opts.Catalog == nil {
		return nil, errors.New("render: gabarits, fichiers statiques et traductions sont obligatoires")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	r := &Renderer{
		pages:   map[language.Tag]map[string]*template.Template{},
		assets:  opts.Assets,
		cat:     opts.Catalog,
		version: opts.Version,
		logger:  logger,
		buffers: sync.Pool{New: func() any { return new(bytes.Buffer) }},
	}

	common, err := fs.Glob(opts.Templates, "partials/*.html")
	if err != nil {
		return nil, err
	}
	common = append([]string{"layout.html"}, common...)
	base, err := template.New("").Option("missingkey=error").
		Funcs(staticFuncs(opts.Assets)).Funcs(placeholderFuncs()).
		ParseFS(opts.Templates, common...)
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}

	pages, err := pageFiles(opts.Templates)
	if err != nil {
		return nil, err
	}
	for _, tag := range opts.Catalog.Languages() {
		r.pages[tag] = map[string]*template.Template{}
		funcs := languageFuncs(opts.Catalog.Localizer(tag))
		for name, file := range pages {
			t, err := base.Clone()
			if err != nil {
				return nil, fmt.Errorf("render: %s : %w", name, err)
			}
			if _, err := t.Funcs(funcs).ParseFS(opts.Templates, file); err != nil {
				return nil, fmt.Errorf("render: %s : %w", name, err)
			}
			page := t.Lookup("layout")
			if page == nil {
				return nil, errors.New("render: layout.html ne définit pas « layout »")
			}
			if err := escapeNow(page); err != nil {
				return nil, fmt.Errorf("render: %s : %w", name, err)
			}
			r.pages[tag][name] = page
		}
	}
	if _, ok := pages[ErrorPage]; !ok {
		return nil, fmt.Errorf("render: page d'erreur %s absente", ErrorPage)
	}
	return r, nil
}

// pageFiles associe le nom de chaque page (« home/index ») à son fichier.
func pageFiles(fsys fs.FS) (map[string]string, error) {
	files, err := fs.Glob(fsys, "*/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		if strings.HasPrefix(f, "partials/") {
			continue
		}
		out[strings.TrimSuffix(f, path.Ext(f))] = f
	}
	return out, nil
}

// escapeNow force l'échappement contextuel, que html/template ne fait qu'à la première
// exécution : une erreur d'échappement sort au démarrage. L'exécution elle-même échoue
// sur des données nil, ce qui est attendu et ignoré.
func escapeNow(t *template.Template) error {
	err := t.Execute(io.Discard, nil)
	var escErr *template.Error
	if errors.As(err, &escErr) {
		return err
	}
	return nil
}

// Pages renvoie les noms des pages connues, pour les tests.
func (r *Renderer) Pages() []string {
	var out []string
	for name := range r.pages[r.cat.Default()] {
		out = append(out, name)
	}
	return out
}

// Render rend la page name avec le modèle de vue v. Il complète Page depuis la requête
// (langue, thème, jeton CSRF, identifiant de requête, version), rend dans un tampon,
// puis écrit le statut et le corps : une erreur de rendu donne une page 500 propre.
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, status int, name string, v View) {
	loc := r.localizer(req)
	p := v.base()
	p.Lang = loc.Lang().String()
	p.Chrome = ChromeFrom(req.Context())
	p.Theme = themeFrom(req)
	if p.Theme == "" && p.Chrome != nil {
		p.Theme = p.Chrome.Theme
	}
	p.CSRFToken = csrfx.Token(req)
	p.RequestID = middleware.RequestIDFrom(req.Context())
	p.Version = r.version
	p.Failed = status >= http.StatusBadRequest && name != ErrorPage

	buf := r.buffers.Get().(*bytes.Buffer)
	buf.Reset()
	defer r.buffers.Put(buf)

	t, ok := r.pages[loc.Lang()][name]
	var err error
	if !ok {
		err = fmt.Errorf("render: page inconnue %q", name)
	} else {
		err = t.Execute(buf, v)
	}
	if err != nil {
		middleware.Logger(req.Context(), r.logger).Error("rendu d'une page", "page", name, "err", err)
		if name == ErrorPage {
			// Dernier recours : la page d'erreur elle-même ne se rend pas.
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		r.Error(w, req, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// errorKeys associe un statut à sa clé d'erreur (error.<clé>.title et .text).
var errorKeys = map[int]string{
	http.StatusBadRequest:          "error.bad_request",
	http.StatusForbidden:           "error.forbidden",
	http.StatusNotFound:            "error.not_found",
	http.StatusMethodNotAllowed:    "error.method_not_allowed",
	http.StatusTooManyRequests:     "error.too_many_requests",
	http.StatusInternalServerError: "error.internal",
}

// ErrorKey renvoie la clé d'erreur d'un statut HTTP (error.internal par défaut).
func ErrorKey(status int) string {
	if k, ok := errorKeys[status]; ok {
		return k
	}
	return "error.internal"
}

// ErrorStatuses renvoie les statuts qui ont une page d'erreur dédiée.
func ErrorStatuses() []int {
	out := make([]int, 0, len(errorKeys))
	for s := range errorKeys {
		out = append(out, s)
	}
	return out
}

type errorView struct {
	Page
	Code    int
	TextKey string
}

// Error rend la page d'erreur traduite d'un statut.
func (r *Renderer) Error(w http.ResponseWriter, req *http.Request, status int) {
	r.ErrorWithKey(w, req, status, ErrorKey(status))
}

// ErrorWithKey rend la page d'erreur d'un statut avec un message précis (clé
// error.<nature>, qui a ses sous-clés title et text), par exemple error.csrf pour un 403.
func (r *Renderer) ErrorWithKey(w http.ResponseWriter, req *http.Request, status int, key string) {
	r.Render(w, req, status, ErrorPage, &errorView{
		Page:    Page{TitleKey: key + ".title"},
		Code:    status,
		TextKey: key + ".text",
	})
}

// localizer renvoie le localiseur posé par le middleware de langue, ou celui que donnent
// ?lang= et Accept-Language pour une réponse produite avant lui.
func (r *Renderer) localizer(req *http.Request) *i18n.Localizer {
	return middleware.Localizer(r.cat, req)
}

func themeFrom(req *http.Request) string {
	c, err := req.Cookie(ThemeCookie)
	if err != nil {
		return ""
	}
	switch c.Value {
	case "light", "dark":
		return c.Value
	default:
		return ""
	}
}
