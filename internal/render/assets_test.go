package render

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func minimalStatic() fstest.MapFS {
	return fstest.MapFS{
		"css/tokens.css":         {Data: []byte(".lotor { --a: 1; }")},
		"css/fonts.css":          {Data: []byte("@font-face { src: url(\"../fonts/f.woff2\"); }")},
		"css/base.css":           {Data: []byte(".lotor body { margin: 0; }")},
		"css/components/btn.css": {Data: []byte(".btn {}")},
		"css/components/a.css":   {Data: []byte(".a {}")},
		"css/screens/home.css":   {Data: []byte(".home {}")},
		"js/theme.js":            {Data: []byte("export {};")},
		"fonts/f.woff2":          {Data: []byte("wOF2")},
		"fonts/OFL.txt":          {Data: []byte("licence")},
		"img/favicon.svg":        {Data: []byte("<svg/>")},
	}
}

func TestAssetsBundleOrderAndURLs(t *testing.T) {
	a, err := NewAssets(minimalStatic())
	if err != nil {
		t.Fatal(err)
	}
	css := string(a.files[StylesheetName].body)
	order := []string{"css/tokens.css", "css/fonts.css", "css/base.css", "css/components/a.css", "css/components/btn.css", "css/screens/home.css"}
	last := -1
	for _, name := range order {
		i := strings.Index(css, "/* "+name+" */")
		if i < 0 || i < last {
			t.Fatalf("%s absent ou hors d'ordre dans la feuille :\n%s", name, css)
		}
		last = i
	}
	url, err := a.URL("js/theme.js")
	if err != nil || url != "/static/"+a.Hash()+"/js/theme.js" || len(a.Hash()) != 16 {
		t.Fatalf("URL = %q, %v", url, err)
	}
	if _, err := a.URL("css/tokens.css"); err == nil {
		t.Fatal("une feuille source est servie seule")
	}
	if _, err := a.URL("js/absent.js"); err == nil {
		t.Fatal("fichier inconnu accepté")
	}
}

func TestAssetsHashChangesWithContent(t *testing.T) {
	a, _ := NewAssets(minimalStatic())
	changed := minimalStatic()
	changed["js/theme.js"] = &fstest.MapFile{Data: []byte("export const x = 1;")}
	b, err := NewAssets(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() == b.Hash() {
		t.Fatal("empreinte inchangée après modification d'un fichier")
	}
	again, _ := NewAssets(minimalStatic())
	if again.Hash() != a.Hash() {
		t.Fatal("empreinte instable")
	}
}

func TestAssetsHandler(t *testing.T) {
	a, _ := NewAssets(minimalStatic())
	h := a.Handler()
	get := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	rec := get(http.MethodGet, "/static/"+a.Hash()+"/css/app.css")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/css; charset=utf-8" ||
		rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || rec.Header().Get("ETag") == "" {
		t.Fatalf("feuille : %d %v", rec.Code, rec.Header())
	}
	if !strings.Contains(rec.Body.String(), ".btn") {
		t.Fatal("feuille concaténée incomplète")
	}
	for path, ctype := range map[string]string{
		"/js/theme.js": "text/javascript; charset=utf-8", "/fonts/f.woff2": "font/woff2",
		"/img/favicon.svg": "image/svg+xml", "/fonts/OFL.txt": "text/plain; charset=utf-8",
	} {
		if rec := get(http.MethodGet, "/static/"+a.Hash()+path); rec.Code != 200 || rec.Header().Get("Content-Type") != ctype {
			t.Errorf("%s : %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if rec := get(http.MethodHead, "/static/"+a.Hash()+"/js/theme.js"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD : %d, %d octets", rec.Code, rec.Body.Len())
	}
	if rec := get(http.MethodGet, "/static/ancienne/js/theme.js"); rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("autre empreinte : %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	for _, path := range []string{"/static/" + a.Hash() + "/js/absent.js", "/static/" + a.Hash() + "/css/tokens.css", "/static/x", "/autre"} {
		if rec := get(http.MethodGet, path); rec.Code != 404 {
			t.Errorf("%s : %d, attendu 404", path, rec.Code)
		}
	}
	if rec := get(http.MethodPost, "/static/"+a.Hash()+"/js/theme.js"); rec.Code != 405 || rec.Header().Get("Allow") == "" {
		t.Errorf("POST : %d", rec.Code)
	}
	etag := get(http.MethodGet, "/static/"+a.Hash()+"/js/theme.js").Header().Get("ETag")
	req := httptest.NewRequest(http.MethodGet, "/static/"+a.Hash()+"/js/theme.js", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match : %d", rec.Code)
	}
}

func TestNewAssetsRejectsUnexpectedFiles(t *testing.T) {
	cases := map[string]func(fstest.MapFS){
		"feuille hors ordre":      func(m fstest.MapFS) { m["css/extra.css"] = &fstest.MapFile{Data: []byte("x")} },
		"feuille obligatoire":     func(m fstest.MapFS) { delete(m, "css/base.css") },
		"type non pris en charge": func(m fstest.MapFS) { m["img/x.gif"] = &fstest.MapFile{Data: []byte("x")} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			m := minimalStatic()
			edit(m)
			if _, err := NewAssets(m); err == nil {
				t.Fatal("accepté")
			}
		})
	}
}

func TestRealAssets(t *testing.T) {
	_, st := realFS(t)
	a, err := NewAssets(st)
	if err != nil {
		t.Fatal(err)
	}
	css := string(a.files[StylesheetName].body)
	for _, want := range []string{"--color-bg: light-dark(", "--sev-critical-bg", "--kev-bg", "--color-ai", "@font-face", ".topbar", ".sidenav", ".site-footer", "@container lotor"} {
		if !strings.Contains(css, want) {
			t.Errorf("feuille : %q absent", want)
		}
	}
	if strings.Contains(css, "@container ogs ") || strings.Contains(css, ".ogs ") {
		t.Error("racine .ogs du design non renommée")
	}
	for _, f := range []string{"fonts/atkinson-hyperlegible-next-latin.woff2", "fonts/atkinson-hyperlegible-mono-latin.woff2",
		"fonts/OFL-atkinson-hyperlegible-next.txt", "fonts/OFL-atkinson-hyperlegible-mono.txt", "js/theme.js"} {
		if _, err := a.URL(f); err != nil {
			t.Errorf("%s : %v", f, err)
		}
	}
	// Chaque url() de la feuille désigne un fichier servi.
	for _, part := range strings.Split(css, `url("../`)[1:] {
		name := part[:strings.Index(part, `"`)]
		if _, err := a.URL(name); err != nil {
			t.Errorf("url(../%s) : fichier absent", name)
		}
	}
}
