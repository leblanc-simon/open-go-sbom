package repoagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/forge"
)

const defaultTestTimeout = 2 * time.Minute

func commitN(n int) string { return fmt.Sprintf("%040x", n) }

var mainRef = forge.Ref{Kind: forge.RefBranch, Name: "main"}

func TestPlanCommits(t *testing.T) {
	c := []string{commitN(2), commitN(3), commitN(4)}
	if got := planCommits(c, commitN(4), 10); strings.Join(got, ",") != strings.Join(c, ",") {
		t.Fatalf("%v", got)
	}
	// Bornés aux plus récents, tête en dernier.
	if got := planCommits(c, commitN(4), 2); strings.Join(got, ",") != commitN(3)+","+commitN(4) {
		t.Fatalf("%v", got)
	}
	// Tête absente de la comparaison (histoire réécrite, recul) : ajoutée en dernier.
	if got := planCommits([]string{commitN(2), "bad"}, commitN(9), 10); strings.Join(got, ",") != commitN(2)+","+commitN(9) {
		t.Fatalf("%v", got)
	}
	if got := planCommits(nil, commitN(9), 10); len(got) != 1 || got[0] != commitN(9) {
		t.Fatalf("%v", got)
	}
}

func TestNewValidates(t *testing.T) {
	f := &fakeForge{name: "fake"}
	if _, err := New(Options{}); err == nil {
		t.Fatal("options vides acceptées")
	}
	if _, err := New(Options{Server: &fakeServer{}, Forges: []forge.Provider{f, f}, Logger: testLogger(io.Discard)}); err == nil {
		t.Fatal("forge en double acceptée")
	}
}

func TestCatchupMapsProjectsToForges(t *testing.T) {
	srv := &fakeServer{projects: []Project{
		{ID: "p1", Slug: "app", ForgeURL: "https://fake.example/acme/app", Refs: []TrackedRef{
			{Ref: mainRef}, {Ref: forge.Ref{Kind: forge.RefTag, Name: "v1"}}, {Ref: forge.Ref{Kind: "host", Name: "x"}},
		}},
		{ID: "p2", Slug: "elsewhere", ForgeURL: "https://other.example/acme/app", Refs: []TrackedRef{{Ref: mainRef}}},
	}}
	logs := &syncBuffer{}
	a := newTestAgent(t, srv, &fakeForge{name: "fake"}, logs)
	a.Catchup(context.Background())
	if a.queue.len() != 2 {
		t.Fatalf("%d références en file", a.queue.len())
	}
	if srv.heartbeats != 1 {
		t.Fatal("pas de signal de vie")
	}
	if !strings.Contains(logs.String(), "dépôt sans forge configurée") {
		t.Fatal("dépôt sans forge non signalé")
	}

	srv.listErr = errors.New("indisponible")
	a.Catchup(context.Background())
	if !strings.Contains(logs.String(), "liste des dépôts confiés en échec") {
		t.Fatal("échec de liste non journalisé")
	}
}

func TestOnPush(t *testing.T) {
	srv := &fakeServer{projects: []Project{
		{ID: "p1", Slug: "app", ForgeURL: "https://fake.example/acme/app", Refs: []TrackedRef{{Ref: mainRef}}},
	}}
	a := newTestAgent(t, srv, &fakeForge{name: "fake"}, io.Discard)
	a.refresh(srv.projects)

	if !a.OnPush("fake", forge.Push{Repo: "ACME/app", Ref: mainRef}) || a.queue.len() != 1 {
		t.Fatal("push sur une référence suivie non mis en file")
	}
	a.OnPush("fake", forge.Push{Repo: "acme/app", Ref: forge.Ref{Kind: forge.RefBranch, Name: "dev"}})
	a.OnPush("fake", forge.Push{Repo: "acme/app", Ref: mainRef, Deleted: true})
	if a.queue.len() != 1 {
		t.Fatal("référence non suivie ou supprimée mise en file")
	}
	// Dépôt inconnu : rattrapage anticipé demandé, rien en file.
	a.OnPush("fake", forge.Push{Repo: "acme/new", Ref: mainRef})
	select {
	case <-a.kick:
	default:
		t.Fatal("pas de rattrapage anticipé")
	}
}

func TestProcessRefSkipsKnownHead(t *testing.T) {
	f := &fakeForge{name: "fake"}
	f.setHead(mainRef, commitN(5))
	srv := &fakeServer{projects: []Project{
		{ID: "p1", Slug: "app", ForgeURL: "https://fake.example/acme/app", Refs: []TrackedRef{{Ref: mainRef, LastCommit: commitN(5)}}},
	}}
	a := newTestAgent(t, srv, f, io.Discard)
	a.refresh(srv.projects)
	a.processRef(context.Background(), refKey{"p1", mainRef})
	if f.compares != 0 || len(srv.uploads) != 0 {
		t.Fatal("tête déjà analysée retraitée")
	}
	// Référence absente de la forge : journalisée, sans envoi.
	logs := &syncBuffer{}
	a = newTestAgent(t, srv, &fakeForge{name: "fake"}, logs)
	a.refresh(srv.projects)
	a.processRef(context.Background(), refKey{"p1", mainRef})
	if !strings.Contains(logs.String(), "résolution de la référence en échec") {
		t.Fatal(logs.String())
	}
	// Référence retirée du catalogue entre-temps : rien.
	a.processRef(context.Background(), refKey{"p9", mainRef})
}

func TestPrepareWorkDirRemovesLeftovers(t *testing.T) {
	a := newTestAgent(t, &fakeServer{}, &fakeForge{name: "fake"}, io.Discard)
	left := filepath.Join(a.opts.Work.Dir, workPrefix+"123", "src")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(a.opts.Work.Dir, "other")
	if err := os.WriteFile(keep, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.prepareWorkDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(left)); !os.IsNotExist(err) {
		t.Fatal("analyse interrompue non supprimée")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("fichier étranger supprimé")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	srv := &fakeServer{}
	a := newTestAgent(t, srv, &fakeForge{name: "fake"}, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := srv.heartbeats
		srv.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run ne s'arrête pas")
	}
}

func TestGitEnvKeepsCredentialsOutOfArgs(t *testing.T) {
	env := gitEnv("/w", "https", forge.Credentials{Username: "x-access-token", Password: "ghs_secret"})
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ALLOW_PROTOCOL=https",
		"=core.symlinks\n", "=core.hooksPath\n", "=http.extraHeader\n", "GIT_LFS_SKIP_SMUDGE=1",
	} {
		if !strings.Contains(joined+"\n", want) {
			t.Errorf("%q absent de l'environnement", want)
		}
	}
	// Le jeton n'apparaît qu'encodé dans l'en-tête, jamais en clair.
	if strings.Contains(joined, "ghs_secret") {
		t.Fatal("jeton en clair dans l'environnement")
	}
	if strings.Contains(strings.Join(gitEnv("/w", "https", forge.Credentials{}), "\n"), "extraHeader") {
		t.Fatal("en-tête d'authentification sans identifiants")
	}
}

func TestReceiver(t *testing.T) {
	f := &fakeForge{name: "fake", secret: "s3cret"}
	var pushes []forge.Push
	accept := true
	logs := &syncBuffer{}
	rc, err := NewReceiver([]forge.Provider{f}, func(name string, p forge.Push) bool {
		if name != "fake" {
			t.Errorf("forge %s", name)
		}
		pushes = append(pushes, p)
		return accept
	}, 64, 0, nil, testLogger(logs))
	if err != nil {
		t.Fatal(err)
	}
	h := rc.Handler()
	send := func(path, secret, delivery, body string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("X-Test-Secret", secret)
		req.Header.Set("X-Test-Delivery", delivery)
		req.Header.Set("X-Test-Repo", "acme/app")
		req.Header.Set("X-Test-Ref", "refs/heads/main")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if c := send("/webhooks/fake", "s3cret", "d1", `{"secret-payload":1}`); c != http.StatusAccepted || len(pushes) != 1 {
		t.Fatalf("push valide : %d", c)
	}
	if c := send("/webhooks/fake", "s3cret", "d1", `{}`); c != http.StatusOK || len(pushes) != 1 {
		t.Fatalf("rejeu : %d, %d pushs", c, len(pushes))
	}
	if c := send("/webhooks/fake", "wrong", "d2", `{"secret-payload":2}`); c != http.StatusUnauthorized || len(pushes) != 1 {
		t.Fatalf("mal signé : %d", c)
	}
	if !strings.Contains(logs.String(), "signature invalide") || strings.Contains(logs.String(), "secret-payload") ||
		strings.Contains(logs.String(), "wrong") {
		t.Fatalf("journal du refus : %s", logs.String())
	}
	if c := send("/webhooks/fake", "s3cret", "d3", strings.Repeat("x", 65)); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("trop gros : %d", c)
	}
	if c := send("/webhooks/fake", "s3cret", "d4", "not json"); c != http.StatusBadRequest {
		t.Fatalf("illisible : %d", c)
	}
	if c := send("/webhooks/fake", "s3cret", "d5", ""); c != http.StatusNoContent {
		t.Fatalf("événement ignoré : %d", c)
	}
	if c := send("/webhooks/unknown", "s3cret", "d6", "{}"); c != http.StatusNotFound {
		t.Fatalf("forge inconnue : %d", c)
	}
	accept = false
	if c := send("/webhooks/fake", "s3cret", "d7", "{}"); c != http.StatusServiceUnavailable {
		t.Fatalf("file pleine : %d", c)
	}
	req := httptest.NewRequest(http.MethodGet, "/webhooks/fake", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET : %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("healthz : %d", w.Code)
	}
}

func TestReceiverRateLimit(t *testing.T) {
	f := &fakeForge{name: "fake", secret: "s"}
	rc, err := NewReceiver([]forge.Provider{f}, func(string, forge.Push) bool { return true }, 64, 2, nil, testLogger(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	h := rc.Handler()
	var last int
	for range 3 {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/fake", strings.NewReader("{}"))
		req.Header.Set("X-Test-Secret", "bad")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("troisième requête : %d", last)
	}
	if _, err := NewReceiver(nil, nil, 1, 1, []string{"not-an-ip"}, testLogger(io.Discard)); err == nil {
		t.Fatal("mandataire invalide accepté")
	}
}

func TestPrintable(t *testing.T) {
	if got := printable("a\nb\x00c" + strings.Repeat("x", 200)); strings.ContainsAny(got, "\n\x00") || len([]rune(got)) != 128 {
		t.Fatalf("%q", got)
	}
}
