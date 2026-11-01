package forge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGitHubSetStatus(t *testing.T) {
	key := testKey(t)
	var mu sync.Mutex
	var perms []map[string]string
	var got map[string]string
	var auth string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/app/installation", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"id": 42})
	})
	mux.HandleFunc("POST /app/installations/42/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		perms = append(perms, body.Permissions)
		n := len(perms)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"token": "ghs_" + string(rune('0'+n)), "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
	})
	mux.HandleFunc("POST /repos/acme/app/statuses/"+sha("a"), func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"id": 1})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	g, err := NewGitHub(GitHubConfig{Name: "gh", APIURL: srv.URL, AppID: "1", PrivateKey: key, WebhookSecret: []byte("x"),
		HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	long := strings.Repeat("é", 200)
	if err := g.SetStatus(ctx, "acme/app", sha("a"), CommitStatus{State: StatusFailure, Context: "lotor", Description: long,
		TargetURL: "https://sbom.example.org/o/acme"}); err != nil {
		t.Fatal(err)
	}
	if got["state"] != "failure" || got["context"] != "lotor" || got["target_url"] != "https://sbom.example.org/o/acme" ||
		len([]rune(got["description"])) != maxStatusDescription {
		t.Fatalf("statut envoyé %v", got)
	}
	if auth != "Bearer ghs_1" || len(perms) != 1 || perms[0]["statuses"] != "write" || perms[0]["contents"] != "" {
		t.Fatalf("jeton %q, permissions %v", auth, perms)
	}
	// Le jeton de statut est distinct de celui du clonage (lecture du contenu seule).
	if _, err := g.Credentials(ctx, "acme/app"); err != nil {
		t.Fatal(err)
	}
	if len(perms) != 2 || perms[1]["contents"] != "read" || perms[1]["statuses"] != "" {
		t.Fatalf("permissions %v", perms)
	}
	for _, bad := range []CommitStatus{{State: "weird", Context: "lotor"}, {State: StatusSuccess}} {
		if err := g.SetStatus(ctx, "acme/app", sha("a"), bad); !errors.Is(err, ErrStatus) {
			t.Errorf("%+v : %v", bad, err)
		}
	}
	if err := g.SetStatus(ctx, "acme/app", "abc", CommitStatus{State: StatusSuccess, Context: "lotor"}); !errors.Is(err, ErrStatus) {
		t.Errorf("commit invalide : %v", err)
	}
}

func TestGitLabSetStatus(t *testing.T) {
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Private-Token") != "glpat-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/api/v4/projects/grp%2Fapp/statuses/"+sha("b") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"id": 1})
	}))
	t.Cleanup(srv.Close)
	g, err := NewGitLab(GitLabConfig{Name: "gl", URL: srv.URL, Token: "glpat-secret", WebhookSecret: []byte("x"), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for state, want := range map[StatusState]string{StatusPending: "pending", StatusSuccess: "success", StatusFailure: "failed",
		StatusError: "canceled"} {
		got = nil
		if err := g.SetStatus(context.Background(), "grp/app", sha("b"), CommitStatus{State: state, Context: "lotor",
			Description: "x", TargetURL: "javascript:alert(1)"}); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0]["state"] != want || got[0]["name"] != "lotor" || got[0]["target_url"] != "" {
			t.Errorf("%s : %v", state, got)
		}
	}
	if err := g.SetStatus(context.Background(), "grp/other", sha("b"), CommitStatus{State: StatusSuccess, Context: "lotor"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("projet inconnu : %v", err)
	}
}
