package agent_test

import (
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/agent"
)

// TestActivityState : règles de l'état d'un agent, par nature.
func TestActivityState(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	old, recent := now.Add(-agent.SilentAfter-time.Minute), now.Add(-time.Hour)
	for name, c := range map[string]struct {
		a    agent.Activity
		want agent.State
	}{
		"désactivé":                       {agent.Activity{Kind: agent.KindHost, LastSeen: &recent, Disabled: true}, agent.StateDisabled},
		"jamais vu":                       {agent.Activity{Kind: agent.KindHost, Created: old}, agent.StatePending},
		"hôte inventorié récemment":       {agent.Activity{Kind: agent.KindHost, LastSeen: &recent, LastInventory: &recent, Created: old}, agent.StateActive},
		"hôte qui répond sans inventaire": {agent.Activity{Kind: agent.KindHost, LastSeen: &recent, LastInventory: &old, Created: old}, agent.StateSilent},
		"hôte neuf sans inventaire":       {agent.Activity{Kind: agent.KindHost, LastSeen: &recent, Created: recent}, agent.StateActive},
		"hôte ancien sans inventaire":     {agent.Activity{Kind: agent.KindHost, LastSeen: &recent, Created: old}, agent.StateSilent},
		"dépôt vu récemment":              {agent.Activity{Kind: agent.KindRepo, LastSeen: &recent, LastInventory: &old, Created: old}, agent.StateActive},
		"dépôt sans contact":              {agent.Activity{Kind: agent.KindRepo, LastSeen: &old, Created: old}, agent.StateSilent},
	} {
		if got := c.a.State(now); got != c.want {
			t.Errorf("%s : %s, %s attendu", name, got, c.want)
		}
	}
}
