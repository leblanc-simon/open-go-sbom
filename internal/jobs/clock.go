package jobs

import "time"

// Clock donne l'heure aux workers et au planificateur : échéances, baux, réessais et
// rétention se calculent avec elle, jamais avec now() de PostgreSQL, pour que les tests
// avancent le temps sans attendre. Les instances doivent donc avoir des horloges
// synchronisées (NTP) : un écart doit rester très inférieur à la durée d'un bail.
// Enqueue, Retry et le planificateur hors tests utilisent l'horloge du système.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapte une fonction en Clock.
type ClockFunc func() time.Time

// Now appelle f.
func (f ClockFunc) Now() time.Time { return f() }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock renvoie l'horloge du système.
func SystemClock() Clock { return systemClock{} }
