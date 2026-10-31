package search

import (
	"sync"
	"time"
)

// MaxExportsPerAccount borne les exports simultanés d'un même compte : sans elle, un seul
// compte qui lit lentement garderait toutes les places de l'instance (SEC-07). Les
// comptes sont créés par les administrateurs d'instance : il faut plusieurs comptes pour
// monopoliser l'instance.
const MaxExportsPerAccount = 1

// ExportLimiter borne les exports d'une instance : un export garde une transaction en
// lecture ouverte pendant qu'il écrit (ADR 0024), donc une connexion du pool ; leur nombre
// simultané, par instance et par compte, et leur durée sont bornés. Partagé par l'écran et
// l'API. Il sert aussi aux réencodages de SBOM, coûteux en mémoire.
type ExportLimiter struct {
	slots   chan struct{}
	timeout time.Duration

	mu    sync.Mutex
	owner map[string]int
}

// NewExportLimiter autorise n exports simultanés, chacun d'au plus timeout.
func NewExportLimiter(n int, timeout time.Duration) *ExportLimiter {
	return &ExportLimiter{slots: make(chan struct{}, max(n, 1)), timeout: timeout, owner: map[string]int{}}
}

// Acquire réserve une place pour owner (le compte, « user:<id> ») sans attendre ; faux si
// toutes les places sont prises ou si owner a déjà MaxExportsPerAccount exports en cours.
// release la rend.
func (l *ExportLimiter) Acquire(owner string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.owner[owner] >= MaxExportsPerAccount {
		return nil, false
	}
	select {
	case l.slots <- struct{}{}:
	default:
		return nil, false
	}
	l.owner[owner]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.owner[owner]--; l.owner[owner] <= 0 {
				delete(l.owner, owner)
			}
			<-l.slots
		})
	}, true
}

// Timeout est la durée maximale d'un export.
func (l *ExportLimiter) Timeout() time.Duration { return l.timeout }
