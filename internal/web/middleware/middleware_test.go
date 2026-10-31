package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/locales"
)

func ok() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
}

func TestRequestIDIgnoresClientValue(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = RequestIDFrom(r.Context()) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, "forged\nvalue")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if len(seen) != 24 || seen == "forged\nvalue" || rec.Header().Get(RequestIDHeader) != seen {
		t.Fatalf("identifiant = %q, en-tête %q", seen, rec.Header().Get(RequestIDHeader))
	}
	if RequestIDFrom(req.Context()) != "" {
		t.Fatal("identifiant hors middleware")
	}
}

func TestLoggerFallback(t *testing.T) {
	fallback := slog.Default()
	if Logger(httptest.NewRequest(http.MethodGet, "/", nil).Context(), fallback) != fallback {
		t.Fatal("journal de repli non utilisé")
	}
}

func TestAccessLogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	fail := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
	AccessLog(logger, func(*http.Request) string { return "192.0.2.1" })(fail).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if !strings.Contains(buf.String(), `"level":"ERROR"`) || !strings.Contains(buf.String(), `"status":503`) || !strings.Contains(buf.String(), `"route":"unmatched"`) {
		t.Fatalf("journal : %s", buf.String())
	}
	buf.Reset()
	AccessLog(logger, func(*http.Request) string { return "192.0.2.1" })(ok()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if !strings.Contains(buf.String(), `"level":"INFO"`) || !strings.Contains(buf.String(), `"status":200`) {
		t.Fatalf("journal : %s", buf.String())
	}
}

func TestRecover(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })

	rec := httptest.NewRecorder()
	Recover(logger, fallback)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 500 {
		t.Fatalf("panique : %d", rec.Code)
	}

	// Une réponse déjà commencée n'est pas réécrite.
	rec = httptest.NewRecorder()
	Recover(logger, fallback)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(202)
		panic("boom")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 202 {
		t.Fatalf("réponse commencée : %d", rec.Code)
	}

	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Fatalf("ErrAbortHandler non relancée : %v", r)
		}
	}()
	Recover(logger, fallback)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestTrackingWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	tw := &trackingWriter{ResponseWriter: rec}
	if tw.Unwrap() != rec {
		t.Fatal("Unwrap")
	}
	_, _ = tw.Write([]byte("x"))
	if !tw.wrote {
		t.Fatal("écriture non notée")
	}
}

func TestTrustedProxies(t *testing.T) {
	if _, err := ParseTrustedProxies([]string{"10.0.0.0/8", "nope"}); err == nil {
		t.Fatal("CIDR invalide accepté")
	}
	p, err := ParseTrustedProxies([]string{" 10.0.0.0/8 ", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"10.1.2.3:4": true, "[::ffff:10.1.2.3]:4": true, "[2001:db8::1]:4": true,
		"192.0.2.1:4": false, "pas une adresse": false, "10.1.2.3": true,
	}
	for remote, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		if got := p.Trusts(req); got != want {
			t.Errorf("Trusts(%q) = %v", remote, got)
		}
	}
}

func TestLanguageOrderAndHeaders(t *testing.T) {
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	var got string
	h := Language(cat, LanguageSources{
		Account: func(*http.Request) string { return "" },
		Org:     func(*http.Request) string { return "en" },
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loc, _ := locale.FromContext(r.Context())
		got = loc.Lang().String()
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got != "en" || rec.Header().Get("Content-Language") != "en" || rec.Header().Get("Vary") != "Accept-Language" {
		t.Fatalf("langue de l'organisation : %q %v", got, rec.Header())
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "fr")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "fr" {
		t.Fatalf("Accept-Language avant l'organisation : %q", got)
	}
	if l := Localizer(cat, httptest.NewRequest(http.MethodGet, "/?lang=en", nil)); l.Lang().String() != "en" {
		t.Fatalf("Localizer hors middleware : %v", l.Lang())
	}
}

func TestHTTPMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewHTTPMetrics(reg)
	for _, method := range []string{http.MethodGet, "BREW"} {
		m.Middleware("ui")(ok()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/", nil))
	}
	if n := testutil.ToFloat64(m.requests.WithLabelValues("ui", "other", "unmatched", "200")); n != 1 {
		t.Fatalf("méthode inventée : %v", n)
	}
	if n := testutil.ToFloat64(m.requests.WithLabelValues("ui", "GET", "unmatched", "200")); n != 1 {
		t.Fatalf("GET : %v", n)
	}
}

func TestSecurityHeadersNoHSTSWithoutDetector(t *testing.T) {
	rec := httptest.NewRecorder()
	SecurityHeaders(SecurityOptions{CSP: CSPAPI})(ok()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("Strict-Transport-Security") != "" || rec.Header().Get("Cache-Control") != "" || rec.Header().Get("Content-Security-Policy") != CSPAPI {
		t.Fatalf("en-têtes : %v", rec.Header())
	}
}
