package repoagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"leblanc.io/open-go-sbom/internal/forge"
)

// Options assemble un agent dépôt.
type Options struct {
	Server  Server
	Forges  []forge.Provider
	Logger  *slog.Logger
	Version string
	Work    WorkConfig
	Catchup CatchupConfig
	// Now remplace l'horloge (tests).
	Now func() time.Time
}

// refKey identifie une référence suivie d'un projet : clé de la file.
type refKey struct {
	project string
	ref     forge.Ref
}

// tracked est une référence suivie, reliée à sa forge.
type tracked struct {
	project Project
	ref     TrackedRef
	forge   forge.Provider
	repo    string
}

// Agent est le pipeline de l'agent dépôt : catalogue des dépôts confiés, file des
// références à analyser, travailleurs (résolution, clonage, Syft, envoi) et rattrapage.
type Agent struct {
	opts    Options
	log     *slog.Logger
	git     gitRunner
	scanner scanner
	queue   *queue[refKey, struct{}]
	now     func() time.Time
	kick    chan struct{}

	mu       sync.RWMutex
	catalog  map[refKey]tracked
	byRepo   map[string][]refKey // forge + "\x00" + dépôt en minuscules
	sent     map[refKey]string   // dernier commit envoyé par cette instance
	failures *boundedSet         // commits en échec définitif (projet + commit)
}

// New construit un agent.
func New(opts Options) (*Agent, error) {
	if opts.Server == nil || len(opts.Forges) == 0 || opts.Logger == nil {
		return nil, errors.New("repoagent: serveur, forges et journal obligatoires")
	}
	names := map[string]bool{}
	for _, f := range opts.Forges {
		if names[f.Name()] {
			return nil, fmt.Errorf("repoagent: forge %q en double", f.Name())
		}
		names[f.Name()] = true
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Agent{
		opts: opts, log: opts.Logger, now: now,
		git:     gitRunner{binary: opts.Work.Git, maxBytes: int64(opts.Work.MaxCloneMiB) << 20, timeout: opts.Work.CloneTimeout},
		scanner: scanner{agentVersion: opts.Version},
		queue:   newQueue[refKey, struct{}](opts.Work.QueueSize),
		kick:    make(chan struct{}, 1),
		catalog: map[refKey]tracked{}, byRepo: map[string][]refKey{}, sent: map[refKey]string{},
		failures: newBoundedSet(10_000),
	}, nil
}

// Run fait tourner l'agent jusqu'à l'annulation de ctx : nettoyage des analyses
// interrompues, travailleurs, puis rattrapage au démarrage et à intervalle.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.prepareWorkDir(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for range a.opts.Work.Parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.work(ctx)
		}()
	}
	a.schedule(ctx)
	wg.Wait()
	return nil
}

// prepareWorkDir crée le répertoire de travail (0700) et supprime les analyses qu'un
// arrêt brutal aurait laissées.
func (a *Agent) prepareWorkDir() error {
	dir := a.opts.Work.Dir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("repoagent: répertoire de travail : %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("repoagent: répertoire de travail : %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), workPrefix) {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("repoagent: nettoyage de %s : %w", e.Name(), err)
			}
		}
	}
	return nil
}

// minKick espace deux rattrapages demandés par des webhooks de dépôts inconnus.
const minKick = time.Minute

// schedule rattrape au démarrage, puis à chaque intervalle ou sur demande.
func (a *Agent) schedule(ctx context.Context) {
	t := time.NewTicker(a.opts.Catchup.Interval)
	defer t.Stop()
	var last time.Time
	for {
		a.Catchup(ctx)
		last = a.now()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.kick:
			if wait := minKick - a.now().Sub(last); wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}
	}
}

// Catchup relit les dépôts confiés, envoie un signal de vie et met en file chaque
// référence suivie : son traitement compare la tête de la référence au dernier commit
// connu et rattrape l'écart.
func (a *Agent) Catchup(ctx context.Context) {
	if err := a.opts.Server.Heartbeat(ctx, a.opts.Version); err != nil && ctx.Err() == nil {
		a.log.Warn("signal de vie en échec", "err", err)
	}
	projects, err := a.opts.Server.Projects(ctx)
	if err != nil {
		if ctx.Err() == nil {
			a.log.Error("liste des dépôts confiés en échec", "err", err)
		}
		return
	}
	keys := a.refresh(projects)
	lost := 0
	for _, k := range keys {
		if !a.queue.push(k, struct{}{}) {
			lost++
		}
	}
	if lost > 0 {
		a.log.Warn("file pleine : références reportées au prochain rattrapage", "count", lost)
	}
	a.log.Info("rattrapage", "projects", len(projects), "refs", len(keys))
}

// refresh remplace le catalogue par la liste du serveur et renvoie les références
// suivies reliées à une forge configurée.
func (a *Agent) refresh(projects []Project) []refKey {
	catalog := map[refKey]tracked{}
	byRepo := map[string][]refKey{}
	var keys []refKey
	for _, p := range projects {
		f, repo, ok := a.forgeOf(p.ForgeURL)
		if !ok {
			a.log.Warn("dépôt sans forge configurée ou hors de allowed_namespaces", "project", p.Slug)
			continue
		}
		for _, r := range p.Refs {
			if r.Ref.Kind != forge.RefBranch && r.Ref.Kind != forge.RefTag {
				continue
			}
			k := refKey{project: p.ID, ref: r.Ref}
			catalog[k] = tracked{project: p, ref: r, forge: f, repo: repo}
			rk := repoKey(f.Name(), repo)
			byRepo[rk] = append(byRepo[rk], k)
			keys = append(keys, k)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.catalog, a.byRepo = catalog, byRepo
	for k := range a.sent {
		if _, ok := catalog[k]; !ok {
			delete(a.sent, k)
		}
	}
	return keys
}

func (a *Agent) forgeOf(forgeURL string) (forge.Provider, string, bool) {
	for _, f := range a.opts.Forges {
		if repo, ok := f.Repo(forgeURL); ok {
			return f, repo, true
		}
	}
	return nil, "", false
}

func repoKey(forgeName, repo string) string { return forgeName + "\x00" + strings.ToLower(repo) }

// OnPush met en file la référence d'un push vérifié pour chaque projet qui la suit. Un
// dépôt inconnu du catalogue (projet confié depuis le dernier rattrapage) déclenche un
// rattrapage anticipé. Faux si la file est pleine.
func (a *Agent) OnPush(forgeName string, p forge.Push) bool {
	if p.Deleted {
		a.log.Info("référence supprimée ignorée", "forge", forgeName, "ref", p.Ref.Name)
		return true
	}
	a.mu.RLock()
	keys := a.byRepo[repoKey(forgeName, p.Repo)]
	a.mu.RUnlock()
	if len(keys) == 0 {
		select {
		case a.kick <- struct{}{}:
		default:
		}
		return true
	}
	ok := true
	for _, k := range keys {
		if k.ref == p.Ref && !a.queue.push(k, struct{}{}) {
			ok = false
		}
	}
	return ok
}

// work traite les références de la file jusqu'à l'annulation de ctx.
func (a *Agent) work(ctx context.Context) {
	for {
		k, _, ok := a.queue.pop(ctx)
		if !ok {
			return
		}
		a.processRef(ctx, k)
		a.queue.done(k)
	}
}

// processRef résout la tête d'une référence et analyse les commits qui manquent au
// serveur, du plus ancien au plus récent : l'instantané courant étant le plus récent par
// date de scan, la tête est toujours envoyée en dernier.
func (a *Agent) processRef(ctx context.Context, k refKey) {
	a.mu.RLock()
	t, ok := a.catalog[k]
	base := a.sent[k]
	a.mu.RUnlock()
	if !ok {
		return
	}
	if base == "" {
		base = t.ref.LastCommit
	}
	log := a.log.With("project", t.project.Slug, "ref", t.ref.Ref.Name)
	head, err := t.forge.ResolveRef(ctx, t.repo, t.ref.Ref)
	if err != nil {
		if ctx.Err() == nil {
			log.Error("résolution de la référence en échec", "err", err)
		}
		return
	}
	if strings.EqualFold(head, base) {
		return
	}
	commits := a.plan(ctx, log, t, base, head)
	for _, c := range commits {
		if ctx.Err() != nil {
			return
		}
		if a.failures.has(t.project.ID + c) {
			continue
		}
		if err := a.analyze(ctx, t, c); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("analyse en échec", "commit", c, "err", err)
			if permanent(err) {
				a.failures.add(t.project.ID + c)
			}
			continue
		}
		a.mu.Lock()
		a.sent[k] = c
		a.mu.Unlock()
		log.Info("SBOM envoyé", "commit", c)
	}
}

// plan liste les commits à analyser : ceux de base (exclu) à head (inclus) pour une
// branche dont un commit est déjà connu, bornés aux plus récents ; head seul pour une
// étiquette, une première analyse ou une comparaison impossible (histoire réécrite).
func (a *Agent) plan(ctx context.Context, log *slog.Logger, t tracked, base, head string) []string {
	if base == "" || t.ref.Ref.Kind != forge.RefBranch {
		return []string{head}
	}
	cmp, err := t.forge.Compare(ctx, t.repo, base, head)
	if err != nil {
		log.Warn("comparaison impossible : tête seule", "err", err)
		return []string{head}
	}
	return planCommits(cmp.Commits, head, a.opts.Catchup.MaxCommits)
}

// planCommits garde les max derniers commits valides d'une comparaison, la tête en
// dernier.
func planCommits(commits []string, head string, max int) []string {
	var out []string
	for _, c := range commits {
		if forge.ValidCommit(c) && c != head {
			out = append(out, c)
		}
	}
	out = append(out, head)
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

// permanent indique une erreur qu'une nouvelle tentative sur le même commit ne
// résoudrait pas.
func permanent(err error) bool {
	return errors.Is(err, ErrTooLarge) || errors.Is(err, ErrRejected) || errors.Is(err, ErrSymlink)
}

// workPrefix préfixe les répertoires d'analyse, supprimés au démarrage s'il en reste.
const workPrefix = "scan-"

// analyze extrait un commit dans un répertoire propre, le catalogue et envoie son SBOM ;
// le répertoire est supprimé quoi qu'il arrive.
func (a *Agent) analyze(ctx context.Context, t tracked, commit string) (err error) {
	work, err := os.MkdirTemp(a.opts.Work.Dir, workPrefix)
	if err != nil {
		return fmt.Errorf("repoagent: répertoire d'analyse : %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(work); rmErr != nil && err == nil {
			err = fmt.Errorf("repoagent: suppression du répertoire d'analyse : %w", rmErr)
		}
	}()
	creds, err := t.forge.Credentials(ctx, t.repo)
	if err != nil {
		return err
	}
	src := filepath.Join(work, "src")
	if err := a.git.checkout(ctx, src, t.forge.CloneURL(t.repo), creds, commit); err != nil {
		return err
	}
	scanCtx, cancel := context.WithTimeout(ctx, a.opts.Work.ScanTimeout)
	defer cancel()
	doc, err := a.scanner.scan(scanCtx, src, t.project.Slug, commit)
	if err != nil {
		return err
	}
	return a.opts.Server.Upload(ctx, Upload{
		ProjectID: t.project.ID, Ref: t.ref.Ref, Commit: commit,
		AgentVersion: a.opts.Version, ScannedAt: a.now().UTC(), SBOM: doc,
	})
}

// boundedSet est un ensemble borné : au-delà de sa capacité, il oublie les plus anciens.
type boundedSet struct {
	mu    sync.Mutex
	max   int
	order []string
	items map[string]bool
}

func newBoundedSet(max int) *boundedSet { return &boundedSet{max: max, items: map[string]bool{}} }

// add ajoute k ; faux s'il y était déjà.
func (s *boundedSet) add(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items[k] {
		return false
	}
	if len(s.order) >= s.max {
		delete(s.items, s.order[0])
		s.order = s.order[1:]
	}
	s.items[k] = true
	s.order = append(s.order, k)
	return true
}

func (s *boundedSet) has(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[k]
}
