//go:build integration

package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
)

func TestRecordAndListInstance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	q := tdb.App.DB()
	if err := audit.RecordInstance(ctx, q, audit.System, audit.Event{Action: "inconnue.action"}); !errors.Is(err, audit.ErrUnknownAction) {
		t.Fatalf("action inconnue : %v", err)
	}
	many := map[string]string{}
	for i := range 20 {
		many[strings.Repeat("k", i+1)] = "v"
	}
	if err := audit.RecordInstance(ctx, q, audit.System, audit.Event{Action: audit.LoginFailed, Details: many}); err == nil {
		t.Fatal("détails non bornés acceptés")
	}
	long := strings.Repeat("é", 400)
	for i := range 3 {
		ev := audit.Event{Action: audit.LoginFailed, TargetLabel: long, Details: map[string]string{"n": string(rune('a' + i))}}
		if err := audit.RecordInstance(ctx, q, audit.Actor{IP: "192.0.2.1", RequestID: "r"}, ev); err != nil {
			t.Fatal(err)
		}
	}
	p1, err := audit.ListInstance(ctx, q, "", 2)
	if err != nil || len(p1.Items) != 2 || p1.NextCursor == "" || p1.Items[0].Details["n"] != "c" {
		t.Fatalf("page 1 : %+v, %v", p1, err)
	}
	if e := p1.Items[0]; len(e.TargetLabel) > 320 || !strings.HasPrefix(long, e.TargetLabel) || e.IP != "192.0.2.1" || e.ActorUserID != 0 {
		t.Fatalf("événement : %+v", e)
	}
	p2, err := audit.ListInstance(ctx, q, p1.NextCursor, 2)
	if err != nil || len(p2.Items) != 1 || p2.NextCursor != "" || p2.Items[0].Details["n"] != "a" {
		t.Fatalf("page 2 : %+v, %v", p2, err)
	}
	if _, err := audit.ListInstance(ctx, q, "x", 2); err == nil {
		t.Fatal("curseur illisible accepté")
	}
	if _, err := audit.ListInstance(ctx, q, "", 0); err == nil {
		t.Fatal("taille 0 acceptée")
	}
}

func TestEveryActionHasAKey(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range audit.Actions() {
		k := a.Key()
		if !strings.HasPrefix(k, "audit.action.") || strings.Count(k, ".") != 2 || seen[k] {
			t.Errorf("clé %q", k)
		}
		seen[k] = true
	}
}
