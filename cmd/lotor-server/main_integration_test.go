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

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/db/migrations"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/grype"
	"leblanc.io/lotor/internal/vuln/grype/grypetest"
)

// binary construit lotor-server une fois pour les tests de ce fichier.
var binary = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "lotor-server-test-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "lotor-server")
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
		"LOTOR_PORT=" + strconv.Itoa(pub),
		"LOTOR_MANAGEMENT_PORT=" + strconv.Itoa(mgmt),
		"LOTOR_DB_DSN=" + tdb.AppDSN,
		"LOTOR_MIGRATION_DSN=" + tdb.OwnerDSN,
		"LOTOR_HTTP_SHUTDOWN_TIMEOUT=5s",
		"LOTOR_LOG_FORMAT=json",
		// Clé de test (32 octets à 0x07) : les secrets TOTP sont chiffrés.
		"LOTOR_SECRETS_KEYS=test:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
		"LOTOR_SECRETS_ACTIVE_KEY=test",
		"LOTOR_BOOTSTRAP_ADMIN_EMAIL=admin@example.org",
		"LOTOR_BOOTSTRAP_ADMIN_PASSWORD=mot de passe temporaire",
		// Jamais de réseau en test : la base de vulnérabilités est importée.
		"LOTOR_VULNDB_OFFLINE=true",
		"LOTOR_VULNDB_DIR=" + t.TempDir(),
		"LOTOR_VULNDB_SYNC_INTERVAL=1s",
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

// readyStatus renvoie le statut de /readyz dès que l'écoute de gestion répond.
func (i *instance) readyStatus() int {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(i.management + "/readyz")
		if err == nil {
			resp.Body.Close()
			return resp.StatusCode
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0
}

// waitMigrated attend que les instances aient appliqué les n migrations.
func waitMigrated(t *testing.T, tdb *dbtest.DB, n int) {
	t.Helper()
	owner := tdb.Owner(t)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var got int
		if err := owner.QueryRow("SELECT count(*) FROM " + db.MigrationsTable).Scan(&got); err == nil && got == n {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("migrations jamais appliquées")
}

// importVulnDB importe une vraie base Grype, vide, comme le ferait l'écran d'import (T11).
func importVulnDB(t *testing.T, tdb *dbtest.DB) {
	t.Helper()
	dir := t.TempDir()
	path, err := grypetest.TinyArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := vuln.NewChecker(vuln.CheckerOptions{Pool: tdb.App, Engine: grype.NewEngine(), Dir: dir, MaxArchive: 1 << 30})
	if _, err := c.Import(context.Background(), path); err != nil {
		t.Fatal(err)
	}
}

func TestServerEndToEnd(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())

	// Deux instances démarrent ensemble sur une base vide : une seule migre.
	a, b := start(t, tdb), start(t, tdb)
	all, err := db.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	// Instances worker : /readyz échoue tant qu'aucune base de vulnérabilités n'est
	// chargée ; une fois la base importée, chacune la synchronise et devient prête.
	waitMigrated(t, tdb, len(all))
	for _, i := range []*instance{a, b} {
		if code := i.readyStatus(); code != http.StatusServiceUnavailable {
			t.Fatalf("/readyz sans base de vulnérabilités : %d\n%s", code, i.out)
		}
	}
	importVulnDB(t, tdb)
	a.waitReady(t)
	b.waitReady(t)
	applied := strings.Count(a.out.String(), `"msg":"migration appliquée"`) + strings.Count(b.out.String(), `"msg":"migration appliquée"`)
	if applied != len(all) {
		t.Fatalf("migrations appliquées par les deux instances = %d, attendu %d\nA:\n%s\nB:\n%s", applied, len(all), a.out, b.out)
	}

	// Le premier administrateur n'est créé qu'une fois, même par deux instances simultanées.
	if n := strings.Count(a.out.String()+b.out.String(), "premier administrateur créé"); n != 1 {
		t.Fatalf("premier administrateur créé %d fois\nA:\n%s\nB:\n%s", n, a.out, b.out)
	}

	// L'accueil d'un visiteur anonyme mène à la connexion, traduite.
	for lang, heading := range map[string]string{"fr": "Connectez-vous avec votre adresse e-mail", "en": "Sign in with your e-mail address"} {
		resp, err := http.Get(a.public + "/login?lang=" + lang)
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
	if !strings.Contains(metrics.String(), "lotor_http_requests_total") || !strings.Contains(metrics.String(), "go_sql_open_connections") ||
		!strings.Contains(metrics.String(), "lotor_vulndb_loaded 1") {
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
		"configuration invalide": {[]string{"LOTOR_DB_DRIVER=sqlite"}, 2, "database.driver (LOTOR_DB_DRIVER)"},
		"rôle superutilisateur":  {[]string{"LOTOR_DB_DSN=" + superDSN}, 1, "superutilisateur"},
		"rôle propriétaire":      {[]string{"LOTOR_DB_DSN=" + tdb.OwnerDSN, "LOTOR_MIGRATION_DSN="}, 1, "propriétaire"},
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
	for name, env := range map[string][]string{"avec migration": nil, "sans migration": {"LOTOR_MIGRATION_DSN="}} {
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
	if err != nil || !strings.HasPrefix(string(out), "lotor-server ") {
		t.Fatalf("--version : %q, %v", out, err)
	}
	out, err = exec.Command(bin, "--help").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "LOTOR_MIGRATION_DSN") {
		t.Fatalf("--help : %v\n%s", err, out)
	}
}
