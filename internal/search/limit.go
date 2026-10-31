package search

import "time"

// ExportLimiter borne les exports d'une instance : un export garde une transaction en
// lecture ouverte pendant qu'il écrit (ADR 0024), donc une connexion du pool ; leur nombre
// simultané et leur durée sont bornés. Partagé par l'écran et l'API.
type ExportLimiter struct {
	slots   chan struct{}
	timeout time.Duration
}

// NewExportLimiter autorise n exports simultanés, chacun d'au plus timeout.
func NewExportLimiter(n int, timeout time.Duration) *ExportLimiter {
	return &ExportLimiter{slots: make(chan struct{}, max(n, 1)), timeout: timeout}
}

// Acquire réserve une place sans attendre ; faux si toutes sont prises. release la rend.
func (l *ExportLimiter) Acquire() (release func(), ok bool) {
	select {
	case l.slots <- struct{}{}:
		return func() { <-l.slots }, true
	default:
		return nil, false
	}
}

// Timeout est la durée maximale d'un export.
func (l *ExportLimiter) Timeout() time.Duration { return l.timeout }
