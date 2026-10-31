//go:build measure

package hostagent

// Mesures et moindre privilège du binaire réel, hors CI (étiquette measure, root requis
// pour changer d'utilisateur) :
//
//	make build GOARCH=amd64
//	OGSBOM_HOST_AGENT_BINARY=$PWD/bin/ogsbom-host-agent go test -tags measure -count=1 -v \
//	    -run TestMeasure ./internal/hostagent/
//
// Le binaire tourne sous l'utilisateur nobody avec la seule capacité CAP_DAC_READ_SEARCH
// (comme l'unité systemd, par setpriv), contre un faux serveur HTTPS, deux fois de suite :
// un envoi, puis un signal de vie. OGSBOM_MEASURE_ROOT choisit la racine (défaut /),
// OGSBOM_MEASURE_EXCLUDE ajoute des exclusions (liste YAML : /root, /home).

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

const nobody = 65534

func measureBinary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("OGSBOM_HOST_AGENT_BINARY")
	if bin == "" {
		t.Skip("OGSBOM_HOST_AGENT_BINARY non défini")
	}
	if os.Geteuid() != 0 {
		t.Skip("root requis pour lancer l'agent sous nobody")
	}
	return bin
}

// realServer est le faux serveur dont l'empreinte rangée est calculée sur le SBOM reçu,
// comme le ferait le serveur.
func realServer(t *testing.T) (*fakeServer, *httptest.Server, string) {
	t.Helper()
	fs := &fakeServer{projectID: uuid.New()}
	fs.fingerprintOf = func(gz []byte) string {
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			return ""
		}
		data, _ := io.ReadAll(zr)
		inv, err := fingerprint(data)
		if err != nil {
			return ""
		}
		return hex.EncodeToString(inv.Fingerprint[:])
	}
	srv := httptest.NewTLSServer(fs)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)
	return fs, srv, ca
}

type run struct {
	wall, user, sys time.Duration
	maxRSS          int64 // Kio
	out             string
	err             error
}

// runAgent lance un cycle oneshot du binaire sous nobody ; withCap donne
// CAP_DAC_READ_SEARCH.
func runAgent(t *testing.T, bin, serverURL, ca, root, stateDir string, withCap bool) run {
	t.Helper()
	cfg := filepath.Join(filepath.Dir(stateDir), "config.yaml")
	yaml := fmt.Sprintf("mode: oneshot\nhostname: srv-mesure\nstate_dir: %s\nenrollment_token_file: %s\nserver:\n  url: %s\n  ca_file: %s\n  retries: 1\nscan:\n  root: %s\n  max_duration: 30m\n  exclude: [%s]\nlogging:\n  level: info\n",
		stateDir, filepath.Join(filepath.Dir(stateDir), "enrollment-token"), serverURL, ca, root, os.Getenv("OGSBOM_MEASURE_EXCLUDE"))
	if err := os.WriteFile(cfg, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--reuid=65534", "--regid=65534", "--clear-groups"}
	if withCap {
		args = append(args, "--inh-caps=+dac_read_search", "--ambient-caps=+dac_read_search")
	}
	args = append(args, bin, "-c", cfg)
	cmd := exec.CommandContext(context.Background(), "setpriv", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	r := run{wall: time.Since(start), out: out.String(), err: err}
	if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
		r.user = time.Duration(ru.Utime.Nano())
		r.sys = time.Duration(ru.Stime.Nano())
		r.maxRSS = ru.Maxrss
	}
	return r
}

func prepareState(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(base, "enrollment-token")
	if err := os.WriteFile(tok, []byte("ogsbom_enr_jeton\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "etat")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{tok, state} {
		if err := os.Chown(p, nobody, nobody); err != nil {
			t.Fatal(err)
		}
	}
	return state
}

// TestMeasureScan mesure deux cycles (envoi, puis signal de vie) sur la racine choisie.
func TestMeasureScan(t *testing.T) {
	bin := measureBinary(t)
	root := os.Getenv("OGSBOM_MEASURE_ROOT")
	if root == "" {
		root = "/"
	}
	fs, srv, ca := realServer(t)
	state := prepareState(t)
	for i, want := range []int{1, 1} {
		r := runAgent(t, bin, srv.URL, ca, root, state, true)
		if r.err != nil {
			t.Fatalf("cycle %d : %v\n%s", i+1, r.err, r.out)
		}
		fs.mu.Lock()
		uploads, size := fs.uploads, len(fs.sbom)
		fs.mu.Unlock()
		if uploads != want {
			t.Errorf("cycle %d : %d envois, %d attendu\n%s", i+1, uploads, want, r.out)
		}
		t.Logf("cycle %d : durée %s, CPU %s (utilisateur %s, système %s), mémoire maximale %d Mio, SBOM gzip %d Kio",
			i+1, r.wall.Round(time.Millisecond), (r.user + r.sys).Round(time.Millisecond), r.user.Round(time.Millisecond),
			r.sys.Round(time.Millisecond), r.maxRSS/1024, size/1024)
		for _, l := range strings.Split(r.out, "\n") {
			if strings.Contains(l, "SBOM envoyé") || strings.Contains(l, "confirmé") {
				t.Log(l)
			}
		}
	}
}

// TestLeastPrivilege : sous nobody, CAP_DAC_READ_SEARCH suffit à lire des bases de paquets
// réservées à root ; sans elle, le scan n'y accède pas.
func TestLeastPrivilege(t *testing.T) {
	bin := measureBinary(t)
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.CopyFS(root, os.DirFS(testRoot(t))); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"var/lib/dpkg", "var/lib/rpm", "lib/apk/db", "usr/lib/python3"} {
		if err := os.Chmod(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chmod(filepath.Dir(root), 0o755)
	for name, withCap := range map[string]bool{"avec CAP_DAC_READ_SEARCH": true, "sans capacité": false} {
		fs, srv, ca := realServer(t)
		r := runAgent(t, bin, srv.URL, ca, root, prepareState(t), withCap)
		fs.mu.Lock()
		sbom := fs.sbom
		fs.mu.Unlock()
		zr, err := gzip.NewReader(bytes.NewReader(sbom))
		var doc []byte
		if err == nil {
			doc, _ = io.ReadAll(zr)
		}
		found := bytes.Contains(doc, []byte(`"name":"openssl"`)) && bytes.Contains(doc, []byte(`"name":"libuuid"`)) &&
			bytes.Contains(doc, []byte(`"name":"musl"`)) && bytes.Contains(doc, []byte(`"name":"requests"`))
		t.Logf("%s : erreur %v, paquets lus : %v", name, r.err, found)
		if withCap && (r.err != nil || !found) {
			t.Errorf("%s : %v\n%s", name, r.err, r.out)
		}
		if !withCap && found {
			t.Errorf("%s : bases réservées à root lues sans la capacité", name)
		}
	}
}
