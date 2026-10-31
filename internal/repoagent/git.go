package repoagent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"leblanc.io/lotor/internal/forge"
)

// Erreurs du clonage.
var (
	// ErrTooLarge : le clone dépasse la taille admise ; erreur définitive pour ce commit.
	ErrTooLarge = errors.New("repoagent: dépôt trop volumineux")
	// ErrCloneTimeout : le clone dépasse sa durée admise.
	ErrCloneTimeout = errors.New("repoagent: clonage trop long")
	// ErrCommitMismatch : le commit extrait n'est pas celui demandé.
	ErrCommitMismatch = errors.New("repoagent: commit extrait inattendu")
	// ErrSymlink : un lien symbolique subsiste dans l'arborescence extraite.
	ErrSymlink = errors.New("repoagent: lien symbolique dans l'arborescence extraite")
)

// sizePoll est la période de mesure de la taille d'un clone en cours.
const sizePoll = 200 * time.Millisecond

// gitRunner extrait un commit précis d'un dépôt distant, sans jamais exécuter un fichier
// du dépôt ni écrire de lien symbolique sur disque.
type gitRunner struct {
	binary   string
	maxBytes int64
	timeout  time.Duration
}

// checkout extrait commit de cloneURL dans dir (qui ne doit pas exister) :
// « git init », « git fetch --depth 1 --no-tags » du seul commit, extraction détachée,
// puis vérification du commit et suppression de .git. Les identifiants passent par
// l'environnement (GIT_CONFIG_*), jamais par les arguments ni par l'URL.
func (g gitRunner) checkout(ctx context.Context, dir, cloneURL string, creds forge.Credentials, commit string) error {
	u, err := url.Parse(cloneURL)
	if err != nil || u.User != nil || u.Scheme == "" {
		return errors.New("repoagent: URL de clonage invalide")
	}
	if !forge.ValidCommit(commit) {
		return errors.New("repoagent: commit invalide")
	}
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	watch, stop := g.watchSize(ctx, dir)
	defer stop()

	env := gitEnv(dir, u.Scheme, creds)
	steps := [][]string{
		{"init", "--quiet", "--template=", dir},
		{"-C", dir, "fetch", "--quiet", "--depth", "1", "--no-tags", "--no-recurse-submodules",
			"--no-write-fetch-head", "--end-of-options", cloneURL, commit},
		{"-C", dir, "checkout", "--quiet", "--detach", commit},
	}
	for _, args := range steps {
		if _, err := g.run(watch, env, args...); err != nil {
			return g.classify(ctx, watch, err)
		}
	}
	out, err := g.run(watch, env, "-C", dir, "rev-parse", "HEAD")
	if err != nil {
		return g.classify(ctx, watch, err)
	}
	if got := strings.TrimSpace(string(out)); got != commit {
		return fmt.Errorf("%w : %s au lieu de %s", ErrCommitMismatch, got, commit)
	}
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		return fmt.Errorf("repoagent: suppression de .git : %w", err)
	}
	if size, err := dirSize(dir); err != nil {
		return err
	} else if size > g.maxBytes {
		return ErrTooLarge
	}
	return ensureNoSymlinks(dir)
}

// classify traduit l'échec d'une commande git selon sa cause.
func (g gitRunner) classify(ctx, watch context.Context, err error) error {
	if errors.Is(context.Cause(watch), ErrTooLarge) {
		return ErrTooLarge
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrCloneTimeout
	}
	return err
}

// watchSize mesure périodiquement la taille de dir et annule le contexte renvoyé, avec
// la cause ErrTooLarge, dès qu'elle dépasse la borne : git est alors tué.
func (g gitRunner) watchSize(ctx context.Context, dir string) (context.Context, func()) {
	watch, cancel := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(sizePoll)
		defer t.Stop()
		for {
			select {
			case <-watch.Done():
				return
			case <-t.C:
				if size, err := dirSize(dir); err == nil && size > g.maxBytes {
					cancel(ErrTooLarge)
					return
				}
			}
		}
	}()
	return watch, func() { cancel(nil); wg.Wait() }
}

// run exécute git ; la sortie d'erreur, bornée, accompagne l'erreur.
func (g gitRunner) run(ctx context.Context, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, g.binary, args...)
	cmd.Env = env
	cmd.Dir = os.TempDir()
	var stdout bytes.Buffer
	stderr := &tailBuffer{max: 2048}
	cmd.Stdout, cmd.Stderr = &stdout, stderr
	killGroup(cmd)
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("repoagent: git %s : %w : %s", args[firstVerb(args)], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// firstVerb renvoie l'indice de la sous-commande git (après « -C dir »).
func firstVerb(args []string) int {
	if len(args) > 2 && args[0] == "-C" {
		return 2
	}
	return 0
}

// gitEnv construit l'environnement complet de git, sans rien hériter de l'agent :
// aucune configuration système ni globale, aucune invite, aucun crochet, aucun lien
// symbolique écrit, LFS inerte, un seul protocole (celui de l'URL de clonage), pas de
// redirection, et les identifiants dans un en-tête HTTP passé par GIT_CONFIG_*.
func gitEnv(home, scheme string, creds forge.Credentials) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + home,
		"LC_ALL=C",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ALLOW_PROTOCOL=" + scheme,
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ASKPASS=/bin/false",
		"SSH_ASKPASS=/bin/false",
	}
	if p := os.Getenv("PATH"); p != "" {
		env[0] = "PATH=" + p
	}
	settings := [][2]string{
		{"core.symlinks", "false"},
		{"core.hooksPath", "/dev/null"},
		{"core.fsmonitor", "false"},
		{"core.autocrlf", "false"},
		{"core.protectNTFS", "true"},
		{"core.protectHFS", "true"},
		{"transfer.fsckObjects", "true"},
		{"protocol.version", "2"},
		{"http.followRedirects", "false"},
		{"credential.helper", ""},
		{"submodule.recurse", "false"},
		{"filter.lfs.required", "false"},
		{"filter.lfs.smudge", ""},
		{"filter.lfs.process", ""},
		{"gc.auto", "0"},
		{"maintenance.auto", "false"},
		{"advice.detachedHead", "false"},
		{"init.defaultBranch", "main"},
	}
	if creds.Password != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		settings = append(settings, [2]string{"http.extraHeader", "Authorization: Basic " + basic})
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(settings)))
	for i, s := range settings {
		n := strconv.Itoa(i)
		env = append(env, "GIT_CONFIG_KEY_"+n+"="+s[0], "GIT_CONFIG_VALUE_"+n+"="+s[1])
	}
	return env
}

// dirSize additionne la taille des fichiers sous dir, sans suivre de lien.
func dirSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total, err
}

// ensureNoSymlinks parcourt l'arborescence par os.Root (aucune sortie possible) et
// refuse tout lien symbolique : core.symlinks=false les écrit en fichiers ordinaires,
// cette vérification en est la garantie.
func ensureNoSymlinks(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("repoagent: ouverture de l'arborescence : %w", err)
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w : %s", ErrSymlink, path)
		}
		return nil
	})
}

// tailBuffer garde les derniers octets écrits (sortie d'erreur de git), sous verrou :
// exec écrit depuis sa propre goroutine.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
