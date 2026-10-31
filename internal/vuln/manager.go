package vuln

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

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
)

// ManagerOptions règle un Manager.
type ManagerOptions struct {
	Pool   *db.Pool
	Engine Engine
	// Dir est le répertoire local des bases (vulndb.dir).
	Dir string
	// SyncInterval est la période de synchronisation de fond sur la cible (Run).
	SyncInterval time.Duration
	Logger       *slog.Logger
}

type loaded struct {
	version Version
	db      Database
}

// Manager tient la copie locale de la base d'une instance worker : il la synchronise sur
// la cible commune (vulndb_state), bascule atomiquement et garde une seule base ouverte,
// derrière un verrou lecture/écriture : une correspondance en cours finit sur la base
// qu'elle a commencée, la bascule attend qu'elle se termine pour fermer l'ancienne.
type Manager struct {
	o ManagerOptions

	syncMu sync.Mutex // une synchronisation à la fois
	mu     sync.RWMutex
	cur    *loaded
}

// NewManager renvoie un Manager sans base chargée.
func NewManager(o ManagerOptions) *Manager {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.SyncInterval <= 0 {
		o.SyncInterval = time.Minute
	}
	return &Manager{o: o}
}

// Loaded renvoie la version chargée ; faux sans base.
func (m *Manager) Loaded() (Version, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cur == nil {
		return Version{}, false
	}
	return m.cur.version, true
}

// Ready échoue tant qu'aucune base n'est chargée (sonde /readyz d'une instance worker).
func (m *Manager) Ready(context.Context) error {
	if _, ok := m.Loaded(); !ok {
		return ErrNoDatabase
	}
	return nil
}

// Ensure synchronise la base locale sur la cible et renvoie la version chargée.
// ErrNoDatabase : aucune cible encore. Un job d'analyse l'appelle avant de travailler :
// un worker en retard se met à jour d'abord.
func (m *Manager) Ensure(ctx context.Context) (Version, error) {
	target, err := TargetVersion(ctx, m.o.Pool.DB())
	if err != nil {
		return Version{}, err
	}
	if target.IsZero() {
		return Version{}, ErrNoDatabase
	}
	if v, ok := m.Loaded(); ok && v.ArchiveID == target.ArchiveID {
		return v, nil
	}
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	// Une autre goroutine a pu synchroniser pendant l'attente.
	if v, ok := m.Loaded(); ok && v.ArchiveID == target.ArchiveID {
		return v, nil
	}
	a, err := GetArchive(ctx, m.o.Pool.DB(), target.ArchiveID)
	if err != nil {
		return Version{}, err
	}
	d, err := m.prepare(ctx, a)
	if err != nil {
		return Version{}, err
	}
	m.swap(&loaded{version: a.Version(), db: d})
	m.o.Logger.Info("base de vulnérabilités chargée", "archive", a.ID, "built", a.Built)
	return a.Version(), nil
}

// prepare ouvre la base de l'archive a, installée au besoin depuis PostgreSQL. Une
// archive dont la somme ne correspond pas n'est jamais installée.
func (m *Manager) prepare(ctx context.Context, a Archive) (Database, error) {
	dir := installDir(m.o.Dir, a)
	if _, err := os.Stat(dir); err == nil {
		d, err := m.open(ctx, dir, a)
		if err == nil {
			return d, nil
		}
		m.o.Logger.Warn("base locale illisible, réinstallation", "archive", a.ID, "err", err)
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(m.o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("vuln: répertoire local : %w", err)
	}
	f, err := os.CreateTemp(m.o.Dir, ".sync-*.archive")
	if err != nil {
		return nil, fmt.Errorf("vuln: fichier de synchronisation : %w", err)
	}
	defer os.Remove(f.Name())
	err = copyArchive(ctx, m.o.Pool, a, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(m.o.Dir, ".install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	if _, err := m.o.Engine.Install(ctx, f.Name(), filepath.Join(staging, "db")); err != nil {
		return nil, err
	}
	if err := os.Rename(filepath.Join(staging, "db"), dir); err != nil {
		return nil, fmt.Errorf("vuln: activation locale : %w", err)
	}
	return m.open(ctx, dir, a)
}

func (m *Manager) open(ctx context.Context, dir string, a Archive) (Database, error) {
	d, err := m.o.Engine.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	if desc := d.Description(); !desc.Built.Equal(a.Built) || desc.Schema != a.Schema {
		_ = d.Close()
		return nil, fmt.Errorf("vuln: base locale %s du %s, attendue du %s", dir, desc.Built, a.Built)
	}
	return d, nil
}

// swap remplace la base chargée ; l'ancienne est fermée une fois les correspondances en
// cours terminées (le verrou en écriture les attend), puis son répertoire supprimé.
func (m *Manager) swap(next *loaded) {
	m.mu.Lock()
	prev := m.cur
	m.cur = next
	m.mu.Unlock()
	if prev != nil {
		if err := prev.db.Close(); err != nil {
			m.o.Logger.Warn("fermeture de l'ancienne base", "err", err)
		}
	}
	m.cleanup(next.version.ArchiveID)
}

// cleanup supprime les répertoires des autres bases et les restes d'opérations
// interrompues. Les fichiers temporaires d'une vérification en cours (Checker) portent
// un autre préfixe et sont laissés.
func (m *Manager) cleanup(keep uuid.UUID) {
	entries, err := os.ReadDir(m.o.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		id, perr := uuid.Parse(name)
		other := perr == nil && id != keep && e.IsDir()
		if other || strings.HasPrefix(name, ".sync-") || strings.HasPrefix(name, ".install-") {
			if err := os.RemoveAll(filepath.Join(m.o.Dir, name)); err != nil {
				m.o.Logger.Warn("nettoyage du répertoire des bases", "path", name, "err", err)
			}
		}
	}
}

// Match confronte un SBOM à la base chargée et indique quelle base a répondu.
func (m *Manager) Match(ctx context.Context, blob []byte) (Result, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cur == nil {
		return Result{}, ErrNoDatabase
	}
	ms, vs, err := m.cur.db.Match(ctx, blob)
	if err != nil {
		return Result{}, err
	}
	return Result{Version: m.cur.version, Matches: ms, Vulnerabilities: vs}, nil
}

// Run synchronise la base locale au démarrage puis toutes les SyncInterval, jusqu'à
// l'annulation de ctx ; il ferme alors la base.
func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(m.o.SyncInterval)
	defer t.Stop()
	for {
		if _, err := m.Ensure(ctx); err != nil && !errors.Is(err, ErrNoDatabase) && ctx.Err() == nil {
			m.o.Logger.Error("synchronisation de la base de vulnérabilités", "err", err)
		}
		select {
		case <-ctx.Done():
			m.close()
			return nil
		case <-t.C:
		}
	}
}

func (m *Manager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != nil {
		_ = m.cur.db.Close()
		m.cur = nil
	}
}
