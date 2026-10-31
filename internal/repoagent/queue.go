package repoagent

import (
	"context"
	"sync"
)

// queue est la file en mémoire des références à analyser : bornée, dédoublonnée par
// référence, et sans deux traitements simultanés d'une même référence (ses commits
// doivent partir dans l'ordre). Elle n'est pas durable : le rattrapage reconstruit le
// travail après un redémarrage.
type queue[K comparable, V any] struct {
	capacity int

	mu      sync.Mutex
	order   []K     // clés en attente, par ordre d'arrivée
	pending map[K]V // tâche en attente par clé
	running map[K]bool
	again   map[K]V // tâche reçue pendant le traitement de sa clé
	ready   chan struct{}
}

func newQueue[K comparable, V any](capacity int) *queue[K, V] {
	return &queue[K, V]{
		capacity: capacity,
		pending:  map[K]V{}, running: map[K]bool{}, again: map[K]V{},
		ready: make(chan struct{}, 1),
	}
}

// push met une tâche en file. Une tâche déjà en attente pour la même clé est remplacée
// par la plus récente ; une clé en cours de traitement sera reprise à la fin de celui-ci.
// Faux si la file est pleine : la tâche est perdue, le prochain rattrapage la refera.
func (q *queue[K, V]) push(k K, v V) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.running[k] {
		if _, ok := q.again[k]; !ok && q.sizeLocked() >= q.capacity {
			return false
		}
		q.again[k] = v
		return true
	}
	if _, ok := q.pending[k]; ok {
		q.pending[k] = v
		return true
	}
	if q.sizeLocked() >= q.capacity {
		return false
	}
	q.pending[k] = v
	q.order = append(q.order, k)
	q.signal()
	return true
}

// pop attend une tâche ; faux quand ctx est annulé. L'appelant appelle done(k) à la fin
// du traitement.
func (q *queue[K, V]) pop(ctx context.Context) (K, V, bool) {
	for {
		q.mu.Lock()
		if len(q.order) > 0 {
			k := q.order[0]
			q.order = q.order[1:]
			v := q.pending[k]
			delete(q.pending, k)
			q.running[k] = true
			if len(q.order) > 0 {
				q.signal()
			}
			q.mu.Unlock()
			return k, v, true
		}
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			var k K
			var v V
			return k, v, false
		case <-q.ready:
		}
	}
}

// done termine le traitement de k et remet en file la tâche reçue entre-temps.
func (q *queue[K, V]) done(k K) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.running, k)
	if v, ok := q.again[k]; ok {
		delete(q.again, k)
		q.pending[k] = v
		q.order = append(q.order, k)
		q.signal()
	}
}

// len renvoie le nombre de tâches en attente (reprises comprises).
func (q *queue[K, V]) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sizeLocked()
}

func (q *queue[K, V]) sizeLocked() int { return len(q.pending) + len(q.again) }

func (q *queue[K, V]) signal() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}
