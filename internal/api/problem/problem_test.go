package problem

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"leblanc.io/open-go-sbom/internal/api/gen"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/pagination"
	"leblanc.io/open-go-sbom/internal/web/middleware"
	"leblanc.io/open-go-sbom/locales"
)

func catalog(t *testing.T) *locale.Catalog {
	t.Helper()
	c, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) gen.Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Fatalf("Content-Type = %q", ct)
	}
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWriteTranslatesTitleAndDetail(t *testing.T) {
	cat := catalog(t)
	for lang, title := range map[string]string{"fr": "Page introuvable", "en": "Page not found"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/x", nil)
		req.Header.Set("Accept-Language", lang)
		rec := httptest.NewRecorder()
		middleware.RequestID(Handler(cat, http.StatusNotFound, KeyNotFound)).ServeHTTP(rec, req)
		p := decode(t, rec)
		if rec.Code != 404 || p.Status != 404 || p.Type != KeyNotFound || p.Title != title {
			t.Fatalf("%s : %d %+v", lang, rec.Code, p)
		}
		if p.Detail == nil || *p.Detail == "" || *p.Instance != "/api/v1/agent/x" || p.RequestId == nil || len(*p.RequestId) != 24 {
			t.Fatalf("%s : champs manquants %+v", lang, p)
		}
		if rec.Header().Get("Content-Language") != lang {
			t.Errorf("Content-Language = %q", rec.Header().Get("Content-Language"))
		}
	}
}

func TestFromPagination(t *testing.T) {
	cat := catalog(t)
	cases := []struct {
		err    error
		key    string
		detail string
	}{
		{&pagination.LimitError{Max: 200}, KeyInvalidLimit, "La taille de page doit être comprise entre 1 et 200."},
		{pagination.ErrInvalidCursor, KeyInvalidCursor, ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		if !FromPagination(rec, httptest.NewRequest(http.MethodGet, "/", nil), cat, c.err) {
			t.Fatalf("%v non traduite", c.err)
		}
		p := decode(t, rec)
		if rec.Code != 400 || p.Type != c.key || (c.detail != "" && *p.Detail != c.detail) {
			t.Fatalf("%v : %d %+v", c.err, rec.Code, p)
		}
	}
	if FromPagination(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), cat, errors.New("autre")) {
		t.Fatal("erreur étrangère traduite")
	}
}

func TestKeysAreTranslated(t *testing.T) {
	keys, err := locales.Keys()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range Keys() {
		for _, suffix := range []string{".title", ".text"} {
			if !slices.Contains(keys, k+suffix) {
				t.Errorf("clé %s%s absente des traductions", k, suffix)
			}
		}
	}
}
