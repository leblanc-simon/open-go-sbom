//go:build integration

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/db/migrations"
)

// binary construit ogsbom-server une fois pour les tests de ce fichier.
var binary = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "ogsbom-server-test-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "ogsbom-server")
	out, err := exec.Command("go", "build", "-o", path, ".").CombinedOutput()
	if err != nil {
		return "", &buildError{out: string(out), err: err}
	}
	return path, nil
})

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// output est la sortie d'un processus, écrite par exec pendant que le test la lit.
type output struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

type instance struct {
	cmd        *exec.Cmd
	out        *output
	public     string
	management string
}

// start lance une instance ; env complète la configuration minimale.
func start(t *testing.T, tdb *dbtest.DB, env ...string) *instance {
	t.Helper()
	bin, err := binary()
	if err != nil {
		t.Fatal(err)
	}
	pub, mgmt := freePort(t), freePort(t)
	cmd := exec.Command(bin, "-c", filepath.Join(t.TempDir(), "absent.yaml"))
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"OGSBOM_PORT=" + strconv.Itoa(pub),
		"OGSBOM_MANAGEMENT_PORT=" + strconv.Itoa(mgmt),
		"OGSBOM_DB_DSN=" + tdb.AppDSN,
		"OGSBOM_MIGRATION_DSN=" + tdb.OwnerDSN,
		"OGSBOM_HTTP_SHUTDOWN_TIMEOUT=5s",
		"OGSBOM_LOG_FORMAT=json",
	}, env...)
	out := &output{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	inst := &instance{cmd: cmd, out: out,
		public: "http://127.0.0.1:" + strconv.Itoa(pub), management: "http://127.0.0.1:" + strconv.Itoa(mgmt)}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return inst
}

func (i *instance) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(i.management + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("instance jamais prête :\n%s", i.out)
}

// exit attend la fin du processus et renvoie son code de sortie.
func (i *instance) exit(t *testing.T) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- i.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("le processus ne s'arrête pas :\n%s", i.out)
	}
	return i.cmd.ProcessState.ExitCode()
}

func TestServerEndToEnd(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())

	// Deux instances démarrent ensemble sur une base vide : une seule migre.
	a, b := start(t, tdb), start(t, tdb)
	a.waitReady(t)
	b.waitReady(t)
	all, err := db.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	applied := strings.Count(a.out.String(), `"msg":"migration appliquée"`) + strings.Count(b.out.String(), `"msg":"migration appliquée"`)
	if applied != len(all) {
		t.Fatalf("migrations appliquées par les deux instances = %d, attendu %d\nA:\n%s\nB:\n%s", applied, len(all), a.out, b.out)
	}

	for lang, heading := range map[string]string{"fr": "Bienvenue sur open-go-sbom", "en": "Welcome to open-go-sbom"} {
		resp, err := http.Get(a.public + "/?lang=" + lang)
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(body.String(), heading) || resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("page d'accueil %s : %d\n%s", lang, resp.StatusCode, body.String())
		}
	}
	resp, err := http.Get(a.management + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	var metrics bytes.Buffer
	_, _ = metrics.ReadFrom(resp.Body)
	resp.Body.Close()
	if !strings.Contains(metrics.String(), "ogsbom_http_requests_total") || !strings.Contains(metrics.String(), "go_sql_open_connections") {
		t.Fatal("métriques attendues absentes")
	}

	// SIGTERM : arrêt propre, code 0.
	for _, i := range []*instance{a, b} {
		if err := i.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if code := i.exit(t); code != 0 {
			t.Fatalf("code de sortie %d après SIGTERM :\n%s", code, i.out)
		}
		if out := i.out.String(); !strings.Contains(out, `"msg":"workers démarrés"`) || !strings.Contains(out, `"msg":"workers arrêtés"`) {
			t.Fatalf("workers non démarrés ou non arrêtés :\n%s", out)
		}
		if !strings.Contains(i.out.String(), "arrêt terminé") {
			t.Fatalf("arrêt non journalisé :\n%s", i.out)
		}
	}
}

func TestServerRefusesToStart(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	_, superDSN := tdb.NewRole(t, "SUPERUSER")

	cases := map[string]struct {
		env  []string
		code int
		want string
	}{
		"configuration invalide": {[]string{"OGSBOM_DB_DRIVER=sqlite"}, 2, "database.driver (OGSBOM_DB_DRIVER)"},
		"rôle superutilisateur":  {[]string{"OGSBOM_DB_DSN=" + superDSN}, 1, "superutilisateur"},
		"rôle propriétaire":      {[]string{"OGSBOM_DB_DSN=" + tdb.OwnerDSN, "OGSBOM_MIGRATION_DSN="}, 1, "propriétaire"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			i := start(t, tdb, c.env...)
			if code := i.exit(t); code != c.code || !strings.Contains(i.out.String(), c.want) {
				t.Fatalf("code %d (attendu %d), sortie :\n%s", code, c.code, i.out)
			}
		})
	}
}

// TestServerRefusesAlteredMigration : une migration enregistrée avec une autre somme
// (fichier modifié après publication) empêche le démarrage.
func TestServerRefusesAlteredMigration(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	if _, err := tdb.Owner(t).ExecContext(context.Background(),
		"UPDATE "+db.MigrationsTable+" SET checksum = repeat('0', 64) WHERE version = 1"); err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string][]string{"avec migration": nil, "sans migration": {"OGSBOM_MIGRATION_DSN="}} {
		t.Run(name, func(t *testing.T) {
			i := start(t, tdb, env...)
			if code := i.exit(t); code != 1 || !strings.Contains(i.out.String(), "migration publiée modifiée") {
				t.Fatalf("code %d, sortie :\n%s", code, i.out)
			}
		})
	}
}

func TestVersionFlag(t *testing.T) {
	bin, err := binary()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "ogsbom-server ") {
		t.Fatalf("--version : %q, %v", out, err)
	}
	out, err = exec.Command(bin, "--help").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OGSBOM_MIGRATION_DSN") {
		t.Fatalf("--help : %v\n%s", err, out)
	}
}
