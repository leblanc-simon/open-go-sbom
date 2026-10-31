package jobs

import "time"

// Backoff calcule le délai avant la tentative suivante d'un job en échec :
//
//	d(n)  = min(Base × 2^(n−1), Max)    n : tentatives déjà faites (n ≥ 1)
//	délai = d(n) × (1 + Jitter × u)      u tiré uniformément dans [0, 1)
//
// Le délai le plus long vaut donc Max × (1 + Jitter). La gigue étale les réessais de jobs
// tombés en échec ensemble (base indisponible quelques secondes, par exemple).
type Backoff struct {
	Base   time.Duration
	Max    time.Duration
	Jitter float64
}

// Valeurs par défaut de Backoff : 10 s, 20 s, 40 s… jusqu'à 30 min, gigue de 20 %.
const (
	DefaultRetryBase   = 10 * time.Second
	DefaultRetryMax    = 30 * time.Minute
	DefaultRetryJitter = 0.2
)

// Delay renvoie le délai après la tentative attempt (1 pour la première), u étant le
// tirage de la gigue dans [0, 1).
func (b Backoff) Delay(attempt int, u float64) time.Duration {
	d := b.Base
	for i := 1; i < attempt && d < b.Max; i++ {
		d *= 2
	}
	d = min(d, b.Max)
	return d + time.Duration(float64(d)*b.Jitter*u)
}
