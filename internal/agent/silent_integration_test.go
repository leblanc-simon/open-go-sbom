//go:build integration

package agent_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/db"
)

// TestSilentCountsEveryPage : le décompte des agents muets parcourt toutes les pages (plus
// de 500 agents) et applique la règle des écrans (StateAt ; pour un agent dépôt, le dernier
// contact) ; les plus anciens silences sortent d'abord.
func TestSilentCountsEveryPage(t *testing.T) {
	t.Parallel()
	f := setup(t)
	o := f.org(t, "parc")
	now := f.clock.Now()
	const n = 1203
	ctx := context.Background()
	if err := f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO agents (org_id, id, kind, name, last_seen_at, disabled_at)
			SELECT $1, gen_random_uuid(), 'repo', 'a-' || lpad(g::text, 5, '0'),
			       CASE WHEN g % 7 = 0 THEN NULL ELSE $2::timestamptz - (g % 20) * interval '1 day' - interval '1 minute' END,
			       CASE WHEN g % 10 = 0 THEN $2::timestamptz END
			  FROM generate_series(1, $3) g`, o, now, n)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := 0
	for g := 1; g <= n; g++ {
		if g%7 != 0 && g%10 != 0 && g%20 >= 7 {
			want++
		}
	}
	var count int
	var longest []agent.Agent
	if err := f.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		var err error
		count, longest, err = agent.Silent(ctx, tx, now, 3, false)
		return err
	}, db.ReadOnly()); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%d agents muets, attendu %d", count, want)
	}
	// Plus long silence : g % 20 = 19, les plus petits noms.
	for i, name := range []string{"a-00019", "a-00039", "a-00059"} {
		if longest[i].Name != name || longest[i].StateAt(now) != agent.StateSilent {
			t.Errorf("silence %d : %s, attendu %s", i, longest[i].Name, name)
		}
	}
	if d := now.Sub(longest[0].SilentSince()); d < 19*24*time.Hour {
		t.Errorf("silence de %s : %s", longest[0].Name, fmt.Sprint(d))
	}
}
