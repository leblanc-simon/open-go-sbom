package web

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"

	"leblanc.io/open-go-base/appconf"

	"leblanc.io/open-go-sbom/internal/api/gen"
	"leblanc.io/open-go-sbom/internal/api/problem"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/web/middleware"
	"leblanc.io/open-go-sbom/internal/web/webtest"
	"leblanc.io/open-go-sbom/locales"
	"leblanc.io/open-go-sbom/web"
)

type fixture struct {
	handler http.Handler
	assets  *render.Assets
	reg     *prometheus.Registry
	logs    *bytes.Buffer
}

func newFixture(t *testing.T, edit func(*RouterOptions)) *fixture {
	t.Helper()
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := web.Templates()
	if err != nil {
		t.Fatal(err)
	}
	st, err := web.Static()
	if err != nil {
		t.Fatal(err)
	}
	assets, err := render.NewAssets(st)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	rd, err := render.New(render.Options{Templates: tpl, Assets: assets, Catalog: cat, Version: "test", Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	o := RouterOptions{
		Logger: logger, Catalog: cat, Renderer: rd, Assets: assets,
		Metrics:        middleware.NewHTTPMetrics(reg),
		RateLimit:      1000,
		TrustedProxies: []string{"10.0.0.0/8"},
		CORS:           appconf.CORS{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"GET", "POST"}, AllowedHeaders: []string{"Authorization"}, MaxAge: 60},
		CSRFSecure:     "auto",
	}
	if edit != nil {
		edit(&o)
	}
	h, err := NewRouter(o)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{handler: h, assets: assets, reg: reg, logs: logs}
}

func (f *fixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) get(path string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	return f.do(req)
}

func assertUIHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Header()
	want := map[string]string{
		"Content-Security-Policy": middleware.CSPInterface,
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "same-origin",
		"X-Frame-Options":         "DENY",
		"Cache-Control":           "no-store",
	}
	for k, v := range want {
		if h.Get(k) != v {
			t.Errorf("%s = %q, attendu %q", k, h.Get(k), v)
		}
	}
	if !strings.Contains(h.Get("Permissions-Policy"), "camera=()") {
		t.Errorf("Permissions-Policy = %q", h.Get("Permissions-Policy"))
	}
	if len(h.Get(middleware.RequestIDHeader)) != 24 {
		t.Errorf("X-Request-Id = %q", h.Get(middleware.RequestIDHeader))
	}
}

func TestHomeInFrenchAndEnglish(t *testing.T) {
	f := newFixture(t, nil)
	cases := map[string]struct {
		path, accept, lang, heading string
	}{
		"défaut français":         {"/", "", "fr", "Bienvenue sur open-go-sbom"},
		"?lang=en":                {"/?lang=en", "fr-FR", "en", "Welcome to open-go-sbom"},
		"Accept-Language anglais": {"/", "en-GB,en;q=0.9", "en", "Welcome to open-go-sbom"},
		"langue indisponible":     {"/", "de-DE", "fr", "Bienvenue sur open-go-sbom"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := f.get(c.path, "Accept-Language", c.accept)
			body := rec.Body.String()
			if rec.Code != 200 || !strings.Contains(body, `<html lang="`+c.lang+`"`) || !strings.Contains(body, c.heading) {
				t.Fatalf("%d\n%s", rec.Code, body)
			}
			if rec.Header().Get("Content-Language") != c.lang {
				t.Errorf("Content-Language = %q", rec.Header().Get("Content-Language"))
			}
			assertUIHeaders(t, rec)
			webtest.AssertAccessible(t, rec.Body.Bytes())
			webtest.AssertNoInlineCode(t, rec.Body.Bytes())
		})
	}
}

func TestHomeThemes(t *testing.T) {
	f := newFixture(t, nil)
	for _, theme := range []string{"light", "dark"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: render.ThemeCookie, Value: theme})
		rec := f.do(req)
		if !strings.Contains(rec.Body.String(), `data-theme="`+theme+`"`) {
			t.Errorf("thème %s non rendu", theme)
		}
		webtest.AssertNoInlineCode(t, rec.Body.Bytes())
	}
	if strings.Contains(f.get("/").Body.String(), "data-theme=") {
		t.Error("sans cookie, le thème doit suivre le système (pas de data-theme)")
	}
}

func TestHeadOnHome(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.do(httptest.NewRequest(http.MethodHead, "/", nil))
	if rec.Code != 200 {
		t.Fatalf("HEAD / : %d", rec.Code)
	}
}

func TestErrorPagesCarrySecurityHeaders(t *testing.T) {
	f := newFixture(t, func(o *RouterOptions) {
		o.extraUI = func(r chi.Router) {
			r.Get("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
		}
	})
	rec := f.get("/absente")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "Page introuvable") {
		t.Fatalf("404 : %d\n%s", rec.Code, rec.Body.String())
	}
	assertUIHeaders(t, rec)
	webtest.AssertAccessible(t, rec.Body.Bytes())

	rec = f.get("/absente?lang=en")
	if !strings.Contains(rec.Body.String(), "Page not found") {
		t.Fatal("404 non traduite en anglais")
	}

	rec = f.get("/panic")
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "Erreur interne") {
		t.Fatalf("panique : %d\n%s", rec.Code, rec.Body.String())
	}
	assertUIHeaders(t, rec)
	if !strings.Contains(f.logs.String(), "panique dans un handler") {
		t.Error("panique non journalisée")
	}

	// 405 : avec un jeton CSRF valide, pour passer la protection des requêtes mutantes.
	first := f.get("/")
	var csrf *http.Cookie
	for _, c := range first.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrf = c
		}
	}
	if csrf == nil {
		t.Fatal("cookie CSRF non posé")
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(csrf)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	rec = f.do(req)
	if rec.Code != 405 || !strings.Contains(rec.Body.String(), "Méthode non autorisée") {
		t.Fatalf("405 : %d\n%s", rec.Code, rec.Body.String())
	}
	assertUIHeaders(t, rec)

	// Sans jeton, une requête mutante de l'interface est refusée par la protection CSRF.
	if rec := f.do(httptest.NewRequest(http.MethodPost, "/", nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("POST sans jeton CSRF : %d", rec.Code)
	}
}

func TestRateLimitPage(t *testing.T) {
	f := newFixture(t, func(o *RouterOptions) { o.RateLimit = 2 })
	var rec *httptest.ResponseRecorder
	for range 3 {
		rec = f.get("/?lang=en")
	}
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Too many requests") {
		t.Fatalf("429 : %d\n%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Security-Policy") != middleware.CSPInterface || rec.Header().Get("Retry-After") == "" {
		t.Errorf("en-têtes du 429 : %v", rec.Header())
	}
	webtest.AssertAccessible(t, rec.Body.Bytes())
	// Les fichiers statiques ne sont pas limités.
	url, _ := f.assets.URL("css/app.css")
	for range 5 {
		if rec := f.get(url); rec.Code != 200 {
			t.Fatalf("fichier statique limité : %d", rec.Code)
		}
	}
}

func TestAPIGroupsHaveNoCSRFAndAnswerProblems(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range []string{"/api/v1/agent/ingestions", "/api/v1/orgs/acme/projects", "/api/v1/agent", "/api/v2/x"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			req.Header.Set("Accept-Language", "en")
			rec := f.do(req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("POST %s : %d (attendu 404 : route absente, et surtout pas 403 CSRF)\n%s", path, rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Content-Type") != problem.ContentType {
				t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
			}
			var p gen.Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Type != problem.KeyNotFound || p.Title != "Page not found" {
				t.Fatalf("problème = %+v, %v", p, err)
			}
			if rec.Header().Get("Content-Security-Policy") != middleware.CSPAPI || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("en-têtes d'API : %v", rec.Header())
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == "csrf_token" {
					t.Error("cookie CSRF posé sur l'API")
				}
			}
		})
	}
}

func TestUserAPICORS(t *testing.T) {
	f := newFixture(t, nil)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/orgs/acme/projects", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := f.do(req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("préflight CORS : %d %v", rec.Code, rec.Header())
	}
	req = httptest.NewRequest(http.MethodOptions, "/api/v1/agent/ingestions", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	if rec := f.do(req); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS ouvert sur l'API agent")
	}
}

func TestHSTSOnlyOverHTTPS(t *testing.T) {
	f := newFixture(t, nil)
	cases := map[string]struct {
		remote, proto string
		tls, want     bool
	}{
		"HTTP direct":                      {"192.0.2.1:1234", "", false, false},
		"TLS natif":                        {"192.0.2.1:1234", "", true, true},
		"mandataire de confiance en HTTPS": {"10.1.2.3:1234", "https", false, true},
		"client qui se déclare en HTTPS":   {"192.0.2.1:1234", "https", false, false},
		"mandataire de confiance en HTTP":  {"10.1.2.3:1234", "http", false, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.remote
			if c.proto != "" {
				req.Header.Set("X-Forwarded-Proto", c.proto)
			}
			if c.tls {
				req.TLS = &tls.ConnectionState{}
			}
			got := f.do(req).Header().Get("Strict-Transport-Security") != ""
			if got != c.want {
				t.Fatalf("HSTS = %v, attendu %v", got, c.want)
			}
		})
	}
}

func TestStaticAssets(t *testing.T) {
	f := newFixture(t, nil)
	body := f.get("/").Body.String()
	for _, name := range []string{"css/app.css", "js/theme.js", "img/favicon.svg"} {
		url, err := f.assets.URL(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, `"`+url+`"`) {
			t.Errorf("la page ne référence pas %s", url)
		}
		rec := f.get(url)
		if rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") ||
			rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s : %d %v", url, rec.Code, rec.Header())
		}
	}
	if rec := f.get("/static/" + f.assets.Hash() + "/absent.css"); rec.Code != 404 {
		t.Errorf("fichier absent : %d", rec.Code)
	}
}

func TestAccessLogAndMetrics(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.get("/?q=secret-term")
	id := rec.Header().Get(middleware.RequestIDHeader)
	logs := f.logs.String()
	if !strings.Contains(logs, `"request_id":"`+id+`"`) || !strings.Contains(logs, `"path":"/"`) || !strings.Contains(logs, `"route":"/"`) {
		t.Fatalf("journal d'accès : %s", logs)
	}
	if strings.Contains(logs, "secret-term") {
		t.Fatal("la chaîne de requête fuit dans le journal")
	}
	f.get("/absente")
	families, err := f.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, fam := range families {
		if fam.GetName() != "ogsbom_http_requests_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			found[labels["group"]+" "+labels["route"]+" "+labels["code"]] = true
		}
	}
	if !found["ui / 200"] || !found["ui unmatched 404"] {
		t.Fatalf("métriques = %v", found)
	}
}

func TestNewRouterValidatesOptions(t *testing.T) {
	if _, err := NewRouter(RouterOptions{}); err == nil {
		t.Fatal("options vides acceptées")
	}
	f := newFixture(t, nil)
	_ = f
	cat, _ := locale.New(locales.FS, ".", "fr")
	_, err := NewRouter(RouterOptions{Logger: slog.Default(), Catalog: cat, Renderer: &render.Renderer{}, Assets: &render.Assets{},
		Metrics: middleware.NewHTTPMetrics(prometheus.NewRegistry()), TrustedProxies: []string{"pas un CIDR"}})
	if err == nil {
		t.Fatal("CIDR invalide accepté")
	}
}
