package forge

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGitHub simule l'API d'une GitHub App : installation, jetons et lecture.
type fakeGitHub struct {
	t   *testing.T
	key *rsa.PrivateKey
	srv *httptest.Server

	mu           sync.Mutex
	tokenCalls   int
	installCalls int
	permissions  map[string]string
	repositories []string
	expires      time.Time
	paths        []string
}

func newFakeGitHub(t *testing.T, key *rsa.PrivateKey) *fakeGitHub {
	f := &fakeGitHub{t: t, key: key, expires: time.Now().Add(time.Hour)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/app/installation", func(w http.ResponseWriter, r *http.Request) {
		f.checkJWT(r)
		f.mu.Lock()
		f.installCalls++
		f.mu.Unlock()
		writeJSON(w, map[string]any{"id": 42})
	})
	mux.HandleFunc("POST /app/installations/42/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		f.checkJWT(r)
		var body struct {
			Permissions  map[string]string `json:"permissions"`
			Repositories []string          `json:"repositories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		f.mu.Lock()
		f.tokenCalls++
		f.permissions, f.repositories = body.Permissions, body.Repositories
		n, exp := f.tokenCalls, f.expires
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"token": "ghs_token" + string(rune('0'+n)), "expires_at": exp.Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /repos/acme/app/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ghs_token") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.EscapedPath())
		f.mu.Unlock()
		switch p := r.URL.EscapedPath(); {
		case p == "/repos/acme/app/commits/heads/feature/x%20y":
			writeJSON(w, map[string]any{"sha": strings.Repeat("AB", 20)})
		case p == "/repos/acme/app/commits/tags/v1.0":
			writeJSON(w, map[string]any{"sha": strings.Repeat("cd", 20)})
		case p == "/repos/acme/app/commits/heads/broken":
			writeJSON(w, map[string]any{"sha": "nope"})
		case strings.HasPrefix(p, "/repos/acme/app/compare/"):
			if p != "/repos/acme/app/compare/"+sha("1")+"..."+sha("3") {
				t.Errorf("comparaison %s", p)
			}
			writeJSON(w, map[string]any{
				"commits": []map[string]string{{"sha": sha("2")}, {"sha": sha("3")}},
				"files":   []map[string]string{{"filename": "go.mod"}},
			})
		case p == "/repos/acme/app/commits/heads/forbidden":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func sha(c string) string { return strings.Repeat(c, 40) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// checkJWT vérifie que l'appel est authentifié par le JWT de l'application.
func (f *fakeGitHub) checkJWT(r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.Count(tok, ".") != 2 || r.Header.Get("X-Github-Api-Version") == "" {
		f.t.Errorf("appel d'application sans JWT : %q", r.Header.Get("Authorization"))
	}
}

func newTestGitHub(t *testing.T, f *fakeGitHub, clock *time.Time) *GitHub {
	t.Helper()
	g, err := NewGitHub(GitHubConfig{
		Name: "github", APIURL: f.srv.URL, AppID: "1", PrivateKey: f.key,
		WebhookSecret: []byte("s3cret"), HTTPClient: f.srv.Client(),
		Now: func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestNewGitHubValidates(t *testing.T) {
	k := testKey(t)
	ok := GitHubConfig{Name: "gh", AppID: "1", PrivateKey: k, WebhookSecret: []byte("x")}
	if _, err := NewGitHub(ok); err != nil {
		t.Fatal(err)
	}
	bad := []func(*GitHubConfig){
		func(c *GitHubConfig) { c.Name = "" },
		func(c *GitHubConfig) { c.AppID = "" },
		func(c *GitHubConfig) { c.PrivateKey = nil },
		func(c *GitHubConfig) { c.WebhookSecret = nil },
		func(c *GitHubConfig) { c.URL = "ftp://github.com" },
		func(c *GitHubConfig) { c.APIURL = "https://u:p@api.github.com" },
	}
	for i, mutate := range bad {
		c := ok
		mutate(&c)
		if _, err := NewGitHub(c); err == nil {
			t.Errorf("configuration %d acceptée", i)
		}
	}
}

func TestGitHubRepo(t *testing.T) {
	g, err := NewGitHub(GitHubConfig{Name: "gh", AppID: "1", PrivateKey: testKey(t), WebhookSecret: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"https://github.com/acme/app":       "acme/app",
		"https://GitHub.com/acme/app.git":   "acme/app",
		"https://github.com/acme/app/":      "acme/app",
		"https://github.com/acme/my.repo_1": "acme/my.repo_1",
	} {
		if got, ok := g.Repo(in); !ok || got != want {
			t.Errorf("Repo(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{
		"https://github.com/acme", "https://github.com/acme/app/tree/main", "http://github.com/acme/app",
		"https://gitlab.com/acme/app", "https://x@github.com/acme/app", "https://github.com/acme/..",
		"https://github.com/acme/a%20b", "::",
	} {
		if got, ok := g.Repo(bad); ok {
			t.Errorf("Repo(%q) = %q accepté", bad, got)
		}
	}
	if got := g.CloneURL("acme/app"); got != "https://github.com/acme/app.git" {
		t.Fatal(got)
	}
	if g.Name() != "gh" || g.Kind() != KindGitHub {
		t.Fatal("nom ou nature")
	}
}

func TestGitHubTokenCachedUntilExpiry(t *testing.T) {
	ctx := context.Background()
	f := newFakeGitHub(t, testKey(t))
	clock := time.Now()
	g := newTestGitHub(t, f, &clock)

	c1, err := g.Credentials(ctx, "acme/app")
	if err != nil {
		t.Fatal(err)
	}
	if c1.Username != "x-access-token" || c1.Password != "ghs_token1" {
		t.Fatalf("identifiants %q", c1.Password)
	}
	if f.permissions["contents"] != "read" || len(f.permissions) != 1 {
		t.Fatalf("permissions demandées %v : la lecture du contenu seule est attendue", f.permissions)
	}
	if len(f.repositories) != 1 || f.repositories[0] != "app" {
		t.Fatalf("dépôts demandés %v : le jeton doit être restreint au seul dépôt (SEC-10)", f.repositories)
	}
	// Second appel, autre casse : même installation, même jeton, sans appel.
	if c2, err := g.Credentials(ctx, "ACME/app"); err != nil || c2.Password != "ghs_token1" {
		t.Fatalf("%v %q", err, c2.Password)
	}
	if f.tokenCalls != 1 || f.installCalls != 1 {
		t.Fatalf("appels : %d jetons, %d installations", f.tokenCalls, f.installCalls)
	}
	// À moins de cinq minutes de l'expiration, le jeton est renouvelé.
	clock = f.expires.Add(-4 * time.Minute)
	if c3, err := g.Credentials(ctx, "acme/app"); err != nil || c3.Password != "ghs_token2" {
		t.Fatalf("%v %q", err, c3.Password)
	}
	if f.installCalls != 1 {
		t.Fatalf("installation recherchée %d fois", f.installCalls)
	}
}

func TestGitHubResolveAndCompare(t *testing.T) {
	ctx := context.Background()
	f := newFakeGitHub(t, testKey(t))
	clock := time.Now()
	g := newTestGitHub(t, f, &clock)

	got, err := g.ResolveRef(ctx, "acme/app", Ref{RefBranch, "feature/x y"})
	if err != nil || got != strings.Repeat("ab", 20) {
		t.Fatalf("branche : %q %v", got, err)
	}
	if got, err := g.ResolveRef(ctx, "acme/app", Ref{RefTag, "v1.0"}); err != nil || got != strings.Repeat("cd", 20) {
		t.Fatalf("étiquette : %q %v", got, err)
	}
	if _, err := g.ResolveRef(ctx, "acme/app", Ref{RefBranch, "absent"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent : %v", err)
	}
	if _, err := g.ResolveRef(ctx, "acme/app", Ref{RefBranch, "forbidden"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("interdit : %v", err)
	}
	if _, err := g.ResolveRef(ctx, "acme/app", Ref{RefBranch, "broken"}); err == nil {
		t.Fatal("commit illisible accepté")
	}
	cmp, err := g.Compare(ctx, "acme/app", sha("1"), sha("3"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cmp.Commits, ",") != sha("2")+","+sha("3") || len(cmp.Files) != 1 || cmp.Files[0] != "go.mod" {
		t.Fatalf("comparaison %+v", cmp)
	}
	// Une installation inconnue (dépôt absent pour l'application) est une erreur claire.
	if _, err := g.Credentials(ctx, "other/repo"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("installation absente : %v", err)
	}
}

func TestGitHubErrorsDoNotLeakToken(t *testing.T) {
	ctx := context.Background()
	f := newFakeGitHub(t, testKey(t))
	clock := time.Now()
	g := newTestGitHub(t, f, &clock)
	_, err := g.ResolveRef(ctx, "acme/app", Ref{RefBranch, "forbidden"})
	if err == nil || strings.Contains(err.Error(), "ghs_") {
		t.Fatalf("erreur %v", err)
	}
}

func TestGitHubFixedInstallation(t *testing.T) {
	f := newFakeGitHub(t, testKey(t))
	clock := time.Now()
	g, err := NewGitHub(GitHubConfig{
		Name: "github", APIURL: f.srv.URL, AppID: "1", PrivateKey: f.key, InstallationID: 42,
		WebhookSecret: []byte("s"), HTTPClient: f.srv.Client(), Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Credentials(context.Background(), "anything/else"); err != nil {
		t.Fatal(err)
	}
	if f.installCalls != 0 {
		t.Fatal("installation recherchée malgré la configuration")
	}
}

func githubSign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGitHubVerifyWebhook(t *testing.T) {
	g, err := NewGitHub(GitHubConfig{Name: "gh", AppID: "1", PrivateKey: testKey(t), WebhookSecret: []byte("s3cret")})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"ref":"refs/heads/main","before":"` + sha("1") + `","after":"` + strings.Repeat("A", 40) +
		`","deleted":false,"repository":{"full_name":"acme/app"}}`)
	h := http.Header{}
	h.Set("X-GitHub-Event", "push")
	h.Set("X-GitHub-Delivery", "d-1")
	h.Set("X-Hub-Signature-256", githubSign("s3cret", body))

	push, err := g.VerifyWebhook(h, body)
	if err != nil || push == nil {
		t.Fatalf("%v %v", push, err)
	}
	want := Push{Delivery: "d-1", Repo: "acme/app", Ref: Ref{RefBranch, "main"}, After: strings.Repeat("a", 40)}
	if *push != want {
		t.Fatalf("%+v", *push)
	}

	invalid := map[string]func(http.Header) ([]byte, http.Header){
		"sans signature": func(h http.Header) ([]byte, http.Header) { h.Del("X-Hub-Signature-256"); return body, h },
		"mauvais secret": func(h http.Header) ([]byte, http.Header) {
			h.Set("X-Hub-Signature-256", githubSign("autre", body))
			return body, h
		},
		"corps modifié": func(h http.Header) ([]byte, http.Header) {
			return []byte(strings.Replace(string(body), "main", "evil", 1)), h
		},
		"sha1 seul": func(h http.Header) ([]byte, http.Header) {
			h.Del("X-Hub-Signature-256")
			h.Set("X-Hub-Signature", "sha1=00")
			return body, h
		},
		"hexadécimal invalide": func(h http.Header) ([]byte, http.Header) {
			h.Set("X-Hub-Signature-256", "sha256=zz")
			return body, h
		},
	}
	for name, mutate := range invalid {
		b, hh := mutate(h.Clone())
		if _, err := g.VerifyWebhook(hh, b); !errors.Is(err, ErrSignature) {
			t.Errorf("%s : %v", name, err)
		}
	}

	// Événement authentique sans intérêt : ignoré.
	ping := []byte(`{"zen":"x"}`)
	hp := http.Header{}
	hp.Set("X-GitHub-Event", "ping")
	hp.Set("X-Hub-Signature-256", githubSign("s3cret", ping))
	if p, err := g.VerifyWebhook(hp, ping); p != nil || err != nil {
		t.Fatalf("ping : %v %v", p, err)
	}

	// Push signé mais illisible.
	for _, b := range [][]byte{[]byte(`{`), []byte(`{"ref":"refs/pull/1","repository":{"full_name":"a/b"}}`), []byte(`{"ref":"refs/heads/x"}`)} {
		hb := h.Clone()
		hb.Set("X-Hub-Signature-256", githubSign("s3cret", b))
		if _, err := g.VerifyWebhook(hb, b); !errors.Is(err, ErrPayload) {
			t.Errorf("%s : %v", b, err)
		}
	}

	// Référence supprimée.
	del := []byte(`{"ref":"refs/tags/v1","after":"` + strings.Repeat("0", 40) + `","deleted":true,"repository":{"full_name":"acme/app"}}`)
	hd := h.Clone()
	hd.Set("X-Hub-Signature-256", githubSign("s3cret", del))
	if p, err := g.VerifyWebhook(hd, del); err != nil || !p.Deleted || p.Ref != (Ref{RefTag, "v1"}) {
		t.Fatalf("suppression : %+v %v", p, err)
	}
}

func TestCallBoundsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = io.Copy(w, io.LimitReader(zeros{}, maxResponse+10))
		case "/teapot":
			w.WriteHeader(http.StatusTeapot)
		default:
			_, _ = w.Write([]byte("{not json"))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	var out map[string]any
	for _, p := range []string{"/big", "/teapot", "/bad"} {
		if err := call(ctx, srv.Client(), http.MethodGet, srv.URL+p, nil, nil, &out); err == nil {
			t.Errorf("%s : pas d'erreur", p)
		}
	}
	if err := call(ctx, srv.Client(), http.MethodGet, "http://127.0.0.1:1/x", nil, nil, nil); err == nil {
		t.Error("transport : pas d'erreur")
	}
	if err := call(ctx, srv.Client(), http.MethodGet, srv.URL+"/x", nil, func() {}, nil); err == nil {
		t.Error("encodage : pas d'erreur")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}
