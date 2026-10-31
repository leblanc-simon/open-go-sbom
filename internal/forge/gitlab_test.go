package forge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newFakeGitLab(t *testing.T) (*GitLab, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Private-Token") != "glpat-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.RequestURI() {
		case "/gitlab/api/v4/projects/grp%2Fsub%2Fapp/repository/branches/feature%2Fx":
			writeJSON(w, map[string]any{"commit": map[string]string{"id": strings.Repeat("AB", 20)}})
		case "/gitlab/api/v4/projects/grp%2Fsub%2Fapp/repository/tags/v2":
			writeJSON(w, map[string]any{"commit": map[string]string{"id": strings.Repeat("cd", 32)}})
		case "/gitlab/api/v4/projects/grp%2Fsub%2Fapp/repository/branches/broken":
			writeJSON(w, map[string]any{"commit": map[string]string{"id": "x"}})
		case "/gitlab/api/v4/projects/grp%2Fsub%2Fapp/repository/compare?from=" + sha("1") + "&to=" + sha("3"):
			writeJSON(w, map[string]any{
				"commits": []map[string]string{{"id": sha("2")}, {"id": sha("3")}},
				"diffs":   []map[string]string{{"new_path": "package-lock.json"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	g, err := NewGitLab(GitLabConfig{
		Name: "gitlab", URL: srv.URL + "/gitlab/", Token: "glpat-secret", WebhookSecret: []byte("hook"),
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, srv
}

func TestNewGitLabValidates(t *testing.T) {
	ok := GitLabConfig{Name: "gl", Token: "t", WebhookSecret: []byte("x")}
	g, err := NewGitLab(ok)
	if err != nil {
		t.Fatal(err)
	}
	if g.CloneURL("a/b") != "https://gitlab.com/a/b.git" || g.Kind() != KindGitLab || g.Name() != "gl" {
		t.Fatal("valeurs par défaut")
	}
	for i, mutate := range []func(*GitLabConfig){
		func(c *GitLabConfig) { c.Name = "" },
		func(c *GitLabConfig) { c.Token = "" },
		func(c *GitLabConfig) { c.WebhookSecret = nil },
		func(c *GitLabConfig) { c.URL = "gitlab.com" },
		func(c *GitLabConfig) { c.URL = "https://gitlab.com/?x=1" },
	} {
		c := ok
		mutate(&c)
		if _, err := NewGitLab(c); err == nil {
			t.Errorf("configuration %d acceptée", i)
		}
	}
}

func TestGitLabRepo(t *testing.T) {
	g, srv := newFakeGitLab(t)
	base := srv.URL + "/gitlab"
	for in, want := range map[string]string{
		base + "/grp/app":                 "grp/app",
		base + "/grp/sub/app.git":         "grp/sub/app",
		base + "/grp/sub/app/-/tree/main": "grp/sub/app",
	} {
		if got, ok := g.Repo(in); !ok || got != want {
			t.Errorf("Repo(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{base + "/grp", srv.URL + "/grp/app", base + "x/grp/app", base + "/grp/../app"} {
		if got, ok := g.Repo(bad); ok {
			t.Errorf("Repo(%q) = %q accepté", bad, got)
		}
	}
	if got := g.CloneURL("grp/app"); got != base+"/grp/app.git" {
		t.Fatal(got)
	}
}

func TestGitLabAPI(t *testing.T) {
	ctx := context.Background()
	g, _ := newFakeGitLab(t)
	if got, err := g.ResolveRef(ctx, "grp/sub/app", Ref{RefBranch, "feature/x"}); err != nil || got != strings.Repeat("ab", 20) {
		t.Fatalf("branche : %q %v", got, err)
	}
	if got, err := g.ResolveRef(ctx, "grp/sub/app", Ref{RefTag, "v2"}); err != nil || got != strings.Repeat("cd", 32) {
		t.Fatalf("étiquette : %q %v", got, err)
	}
	if _, err := g.ResolveRef(ctx, "grp/sub/app", Ref{RefBranch, "absent"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absente : %v", err)
	}
	if _, err := g.ResolveRef(ctx, "grp/sub/app", Ref{RefBranch, "broken"}); err == nil {
		t.Fatal("commit illisible accepté")
	}
	cmp, err := g.Compare(ctx, "grp/sub/app", sha("1"), sha("3"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cmp.Commits, ",") != sha("2")+","+sha("3") || len(cmp.Files) != 1 {
		t.Fatalf("%+v", cmp)
	}
	c, err := g.Credentials(ctx, "grp/app")
	if err != nil || c.Username != "oauth2" || c.Password != "glpat-secret" {
		t.Fatal("identifiants")
	}
	bad, err := NewGitLab(GitLabConfig{Name: "x", URL: "http://127.0.0.1:1", Token: "wrong", WebhookSecret: []byte("s")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.ResolveRef(ctx, "a/b", Ref{RefBranch, "main"}); err == nil {
		t.Fatal("pas d'erreur de transport")
	}
}

func TestGitLabDeniedToken(t *testing.T) {
	_, srv := newFakeGitLab(t)
	g, err := NewGitLab(GitLabConfig{Name: "x", URL: srv.URL + "/gitlab", Token: "wrong", WebhookSecret: []byte("s"), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.ResolveRef(context.Background(), "grp/sub/app", Ref{RefBranch, "feature/x"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("%v", err)
	}
}

func TestGitLabVerifyWebhook(t *testing.T) {
	g, _ := newFakeGitLab(t)
	body := []byte(`{"object_kind":"push","ref":"refs/heads/main","before":"` + sha("1") + `","after":"` + sha("2") +
		`","project":{"path_with_namespace":"grp/sub/app"}}`)
	h := http.Header{}
	h.Set("X-Gitlab-Token", "hook")
	h.Set("X-Gitlab-Event", "Push Hook")
	h.Set("X-Gitlab-Event-UUID", "u-1")
	p, err := g.VerifyWebhook(h, body)
	if err != nil || p == nil {
		t.Fatalf("%v %v", p, err)
	}
	if *p != (Push{Delivery: "u-1", Repo: "grp/sub/app", Ref: Ref{RefBranch, "main"}, After: sha("2")}) {
		t.Fatalf("%+v", *p)
	}

	for name, token := range map[string]string{"absent": "", "faux": "hoo", "plus long": "hook-and-more"} {
		hh := h.Clone()
		hh.Set("X-Gitlab-Token", token)
		if _, err := g.VerifyWebhook(hh, body); !errors.Is(err, ErrSignature) {
			t.Errorf("%s : %v", name, err)
		}
	}

	tag := []byte(`{"ref":"refs/tags/v2","after":"` + strings.Repeat("0", 40) + `","project":{"path_with_namespace":"grp/sub/app"}}`)
	ht := h.Clone()
	ht.Set("X-Gitlab-Event", "Tag Push Hook")
	ht.Del("X-Gitlab-Event-UUID")
	ht.Set("Idempotency-Key", "k-1")
	if p, err := g.VerifyWebhook(ht, tag); err != nil || !p.Deleted || p.Ref != (Ref{RefTag, "v2"}) || p.Delivery != "k-1" {
		t.Fatalf("étiquette : %+v %v", p, err)
	}

	hm := h.Clone()
	hm.Set("X-Gitlab-Event", "Merge Request Hook")
	if p, err := g.VerifyWebhook(hm, body); p != nil || err != nil {
		t.Fatalf("autre événement : %v %v", p, err)
	}
	for _, b := range []string{`[`, `{"ref":"main","project":{"path_with_namespace":"a/b"}}`, `{"ref":"refs/heads/a"}`} {
		if _, err := g.VerifyWebhook(h, []byte(b)); !errors.Is(err, ErrPayload) {
			t.Errorf("%s : %v", b, err)
		}
	}
}
