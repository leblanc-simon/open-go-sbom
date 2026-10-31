package repoagent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueueDeduplicates(t *testing.T) {
	q := newQueue[string, int](10)
	q.push("a", 1)
	q.push("b", 1)
	q.push("a", 2) // remplace la tâche en attente, sans doublon
	if q.len() != 2 {
		t.Fatalf("taille %d", q.len())
	}
	ctx := context.Background()
	k, v, _ := q.pop(ctx)
	if k != "a" || v != 2 {
		t.Fatalf("%s %d : ordre d'arrivée et dernière valeur attendus", k, v)
	}
	k, _, _ = q.pop(ctx)
	if k != "b" {
		t.Fatal(k)
	}
}

func TestQueueBounded(t *testing.T) {
	q := newQueue[int, struct{}](2)
	if !q.push(1, struct{}{}) || !q.push(2, struct{}{}) {
		t.Fatal("refus sous la capacité")
	}
	if q.push(3, struct{}{}) {
		t.Fatal("file pleine acceptée")
	}
	if !q.push(1, struct{}{}) {
		t.Fatal("doublon refusé alors qu'il ne prend pas de place")
	}
}

func TestQueueRerunsKeyAfterCurrentRun(t *testing.T) {
	q := newQueue[string, int](10)
	ctx := context.Background()
	q.push("a", 1)
	k, _, _ := q.pop(ctx)
	// Reçu pendant le traitement : ni perdu, ni traité en parallèle.
	q.push("a", 2)
	q.push("a", 3)
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, _, ok := q.pop(short); ok {
		t.Fatal("la clé en cours a été rendue une seconde fois")
	}
	q.done(k)
	k, v, ok := q.pop(ctx)
	if !ok || k != "a" || v != 3 {
		t.Fatalf("%s %d %v", k, v, ok)
	}
	q.done(k)
	if q.len() != 0 {
		t.Fatal("reprise en double")
	}
}

func TestQueueRunningKeyRespectsCapacity(t *testing.T) {
	q := newQueue[int, struct{}](1)
	q.push(1, struct{}{})
	k, _, _ := q.pop(context.Background())
	q.push(2, struct{}{})
	if q.push(k, struct{}{}) {
		t.Fatal("reprise acceptée dans une file pleine")
	}
}

func TestQueueNeverRunsAKeyTwiceAtOnce(t *testing.T) {
	q := newQueue[int, struct{}](100)
	ctx, cancel := context.WithCancel(context.Background())
	var running [5]atomic.Int32
	var processed atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				k, _, ok := q.pop(ctx)
				if !ok {
					return
				}
				if running[k].Add(1) != 1 {
					t.Errorf("clé %d traitée deux fois en même temps", k)
				}
				time.Sleep(time.Millisecond)
				running[k].Add(-1)
				processed.Add(1)
				q.done(k)
			}
		}()
	}
	for i := range 200 {
		q.push(i%5, struct{}{})
		if i%7 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for q.len() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	wg.Wait()
	if processed.Load() == 0 || q.len() != 0 {
		t.Fatalf("%d traités, %d restants", processed.Load(), q.len())
	}
}

func TestBoundedSetForgetsOldest(t *testing.T) {
	s := newBoundedSet(2)
	if !s.add("a") || s.add("a") || !s.add("b") || !s.add("c") {
		t.Fatal("ajouts")
	}
	if s.has("a") || !s.has("b") || !s.has("c") {
		t.Fatal("le plus ancien devait être oublié")
	}
}
