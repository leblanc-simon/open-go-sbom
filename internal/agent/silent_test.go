package agent

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestSilentAfterSevenDays : décision de T10, un agent est muet au-delà de 7 jours sans
// contact, pas à 7 jours pile.
func TestSilentAfterSevenDays(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	cases := []struct {
		seen     *time.Time
		disabled bool
		want     State
	}{
		{nil, false, StatePending},
		{at(7 * 24 * time.Hour), false, StateActive},
		{at(7*24*time.Hour + time.Second), false, StateSilent},
		{at(30 * 24 * time.Hour), true, StateDisabled},
	}
	for _, c := range cases {
		if got := StateOf(c.seen, c.disabled, now); got != c.want {
			t.Errorf("StateOf(%v, %v) = %s, attendu %s", c.seen, c.disabled, got, c.want)
		}
	}
}

func TestKeepLongest(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	mk := func(name string, days int) Agent {
		seen := base.AddDate(0, 0, days)
		return Agent{ID: uuid.NewSHA1(uuid.Nil, []byte(name)), Name: name, LastSeenAt: &seen}
	}
	var list []Agent
	for _, a := range []Agent{mk("c", 3), mk("a", 1), mk("d", 5), mk("b", 1), mk("e", 0)} {
		list = keepLongest(list, a, 3)
	}
	var names []string
	for _, a := range list {
		names = append(names, a.Name)
	}
	if len(names) != 3 || names[0] != "e" || names[1] != "a" || names[2] != "b" {
		t.Fatalf("plus longs silences : %v", names)
	}
	if got := keepLongest(nil, mk("x", 0), 0); got != nil {
		t.Fatalf("keep nul : %v", got)
	}
	if (Agent{}).SilentSince() != (time.Time{}) {
		t.Fatal("agent jamais vu : silence depuis l'instant zéro attendu")
	}
}
