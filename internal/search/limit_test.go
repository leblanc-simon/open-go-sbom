package search

import (
	"sync"
	"testing"
	"time"
)

// TestExportLimiterPerAccount (SEC-07) : un compte ne prend qu'une place à la fois ; les
// autres comptes gardent l'accès jusqu'au plafond de l'instance.
func TestExportLimiterPerAccount(t *testing.T) {
	l := NewExportLimiter(2, time.Minute)
	first, ok := l.Acquire("user:1")
	if !ok {
		t.Fatal("première place refusée")
	}
	if _, ok := l.Acquire("user:1"); ok {
		t.Fatal("second export simultané du même compte accepté")
	}
	second, ok := l.Acquire("user:2")
	if !ok {
		t.Fatal("place refusée à un autre compte")
	}
	if _, ok := l.Acquire("user:3"); ok {
		t.Fatal("plafond de l'instance dépassé")
	}
	first()
	first() // une seconde libération ne rend rien de plus
	if _, ok := l.Acquire("user:1"); !ok {
		t.Fatal("place non rendue")
	}
	if _, ok := l.Acquire("user:3"); ok {
		t.Fatal("double libération : place rendue deux fois")
	}
	second()
	if len(l.owner) != 1 {
		t.Errorf("comptes suivis : %v", l.owner)
	}
}

func TestExportLimiterConcurrent(t *testing.T) {
	l := NewExportLimiter(3, time.Minute)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			if release, ok := l.Acquire(string(rune('a' + i%5))); ok {
				release()
			}
		})
	}
	wg.Wait()
	if len(l.slots) != 0 || len(l.owner) != 0 {
		t.Fatalf("places restées prises : %d, %v", len(l.slots), l.owner)
	}
}
