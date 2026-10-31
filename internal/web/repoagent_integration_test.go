//go:build integration

package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/forge"
	"leblanc.io/open-go-sbom/internal/ingest"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/repoagent"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// localForge est une GitHub App dont seuls les webhooks sont réels (signature
// X-Hub-Signature-256) ; le dépôt est un dépôt nu local, lu par git.
type localForge struct {
	*forge.GitHub
	t    *testing.T
	bare string
}

func (f localForge) Repo(u string) (string, bool) {
	return "acme/app", u == "https://forge.test/acme/app"
}

func (f localForge) CloneURL(string) string { return "file://" + f.bare }

func (f localForge) Credentials(context.Context, string) (forge.Credentials, error) {
	return forge.Credentials{}, nil
}

func (f localForge) ResolveRef(_ context.Context, _ string, ref forge.Ref) (string, error) {
	return localGit(f.t, f.bare, "rev-parse", "refs/heads/"+ref.Name), nil
}

func (f localForge) Compare(_ context.Context, _ string, base, head string) (forge.Comparison, error) {
	return forge.Comparison{Commits: strings.Fields(localGit(f.t, f.bare, "rev-list", "--reverse", base+".."+head))}, nil
}

func localGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=T", "-c", "user.email=t@example.org", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v : %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commitFile ajoute un fichier dans la copie de travail, valide et publie dans le dépôt nu.
func commitFile(t *testing.T, work, bare, name, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	localGit(t, work, "add", "-A")
	localGit(t, work, "commit", "--quiet", "-m", name)
	localGit(t, work, "push", "--quiet", bare, "main")
	return localGit(t, work, "rev-parse", "HEAD")
}

// TestRepoAgentAgainstServer : agent dépôt réel contre le serveur réel. Un push signé
// produit un instantané pour son commit ; un push mal signé est refusé ; un redémarrage
// de l'agent rattrape le commit manqué pendant son absence.
func TestRepoAgentAgainstServer(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	ag, tok, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, "forge", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.projects.Create(ctx, audit.System, o.ID, project.Input{
		Kind: project.KindRepo, Name: "App", ForgeURL: "https://forge.test/acme/app", Branches: []string{"main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.projects.AssignAgent(ctx, audit.System, o.ID, p.Slug, &ag.ID); err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	work, bare := filepath.Join(base, "work"), filepath.Join(base, "app.git")
	localGit(t, base, "init", "--quiet", work)
	localGit(t, base, "init", "--quiet", "--bare", bare)
	c1 := commitFile(t, work, bare, "go.mod", "module example.org/app\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "hook-secret"
	gh, err := forge.NewGitHub(forge.GitHubConfig{Name: "github", AppID: "1", PrivateKey: key, WebhookSecret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	provider := localForge{GitHub: gh, t: t, bare: bare}
	server, err := repoagent.NewAPIServer(repoagent.ServerConfig{URL: a.srv.URL, Timeout: 30 * time.Second}, tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	workDir := t.TempDir()
	start := func() (*repoagent.Agent, func()) {
		ra, err := repoagent.New(repoagent.Options{
			Server: server, Forges: []forge.Provider{provider}, Logger: newTextLogger(logs), Version: "1.0.0",
			Work: repoagent.WorkConfig{Dir: workDir, Parallelism: 1, QueueSize: 10, CloneTimeout: time.Minute,
				ScanTimeout: 2 * time.Minute, MaxCloneMiB: 64, Git: "git"},
			Catchup: repoagent.CatchupConfig{Interval: time.Hour, MaxCommits: 20},
		})
		if err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error)
		go func() { done <- ra.Run(runCtx) }()
		return ra, func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}

	// Premier démarrage : la référence n'a pas d'instantané, la tête est analysée.
	ra, stop := start()
	snapshotFor(t, a, o.ID, p.ID.String(), c1)

	rc, err := repoagent.NewReceiver([]forge.Provider{provider}, ra.OnPush, 1<<20, 0, nil, newTextLogger(logs))
	if err != nil {
		t.Fatal(err)
	}
	hooks := httptest.NewServer(rc.Handler())
	defer hooks.Close()

	c2 := commitFile(t, work, bare, "requirements.txt", "requests==2.31.0\n")
	if code := pushHook(t, hooks.URL, "wrong", "d1"); code != http.StatusUnauthorized {
		t.Fatalf("push mal signé : %d", code)
	}
	if code := pushHook(t, hooks.URL, secret, "d2"); code != http.StatusAccepted {
		t.Fatalf("push signé : %d", code)
	}
	snapshotFor(t, a, o.ID, p.ID.String(), c2)
	stop()

	// Commit publié pendant l'arrêt de l'agent : rattrapé au redémarrage.
	c3 := commitFile(t, work, bare, "package.json", `{"name":"app","version":"1.0.0"}`)
	_, stop = start()
	snapshotFor(t, a, o.ID, p.ID.String(), c3)
	stop()

	if strings.Contains(logs.String(), tok.Plaintext) || strings.Contains(logs.String(), secret) {
		t.Fatal("secret dans les journaux")
	}
	if entries, _ := os.ReadDir(workDir); len(entries) != 0 {
		t.Fatalf("fichiers résiduels : %v", entries)
	}
}

func pushHook(t *testing.T, url, secret, delivery string) int {
	t.Helper()
	body := []byte(`{"ref":"refs/heads/main","after":"` + strings.Repeat("a", 40) + `","repository":{"full_name":"acme/app"}}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, url+"/webhooks/github", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// snapshotFor attend l'ingestion du commit, la décode comme le ferait le worker et vérifie
// l'instantané produit.
func snapshotFor(t *testing.T, a *app, org tenant.OrgID, projectID, commit string) {
	t.Helper()
	ctx := context.Background()
	pid := mustUUID(t, projectID)
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		recent, err := a.ingest.Recent(ctx, org, pid, 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range recent {
			if in.Commit != commit {
				continue
			}
			if err := a.ingest.Decode(ctx, org, in.ID); err != nil {
				t.Fatal(err)
			}
			page, err := a.inv.Snapshots(ctx, org, pid, in.RefID, "", 50)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range page.Items {
				if s.Commit == commit {
					if s.AgentVersion != "1.0.0" {
						t.Fatalf("version d'agent %q", s.AgentVersion)
					}
					return
				}
			}
			again, _ := a.ingest.Recent(ctx, org, pid, 20)
			for _, x := range again {
				if x.ID == in.ID && x.Status == ingest.StatusFailed {
					t.Fatalf("ingestion en échec : %s %s", x.ErrorKey, x.ErrorDetail)
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("aucun instantané pour %s", commit)
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newTextLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
