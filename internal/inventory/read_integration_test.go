//go:build integration

package inventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/pagination"
	"leblanc.io/open-go-sbom/internal/sbom"
)

func TestReadSnapshots(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	svc := NewService(tdb.App)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	var ids []uuid.UUID
	for i := range 5 {
		ids = append(ids, f.store(t, f.repoRecord(commit(i+1), components(2+i%2, "1.0.0"), t0.Add(time.Duration(i)*time.Minute))).SnapshotID)
	}
	host := f.store(t, f.hostRecord(components(1, "1.0.0"), t0))

	page, err := svc.Snapshots(ctx, f.org, f.repo, uuid.Nil, "", 2)
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" || page.Items[0].ID != ids[4] || !page.Items[0].Current {
		t.Fatalf("première page %+v, %v", page, err)
	}
	s := page.Items[0]
	if s.Commit != commit(5) || s.RefName != "main" || s.RefKind != "branch" || s.AgentName != "agent" || s.AgentID == nil ||
		s.Counts.Total != 2 || s.Counts.Syft != 2 || s.Format != sbom.FormatCycloneDX {
		t.Errorf("instantané %+v", s)
	}
	seen := len(page.Items)
	for page.NextCursor != "" {
		if page, err = svc.Snapshots(ctx, f.org, f.repo, f.main, page.NextCursor, 2); err != nil {
			t.Fatal(err)
		}
		seen += len(page.Items)
		for _, s := range page.Items {
			if s.Current {
				t.Error("un seul instantané courant par référence")
			}
		}
	}
	if seen != 5 {
		t.Errorf("%d instantanés parcourus", seen)
	}
	if _, err := svc.Snapshots(ctx, f.org, f.repo, uuid.Nil, "", SnapshotPageMax+1); err == nil {
		t.Error("taille de page non bornée")
	}
	if _, err := svc.Snapshots(ctx, f.org, f.repo, uuid.Nil, "illisible", 2); !errors.Is(err, pagination.ErrInvalidCursor) {
		t.Errorf("curseur illisible : %v", err)
	}

	got, err := svc.Snapshot(ctx, f.org, f.host, host.SnapshotID)
	if err != nil || got.Commit != "" || got.AgentID != nil || got.RefKind != "host" || !got.Current {
		t.Errorf("instantané d'hôte %+v, %v", got, err)
	}
	if _, err := svc.Snapshot(ctx, f.org, f.repo, host.SnapshotID); !errors.Is(err, ErrNotFound) {
		t.Errorf("instantané d'un autre projet : %v", err)
	}

	states, err := svc.RefStates(ctx, f.org, f.repo)
	if err != nil || len(states) != 1 || states[0].Snapshots != 5 || states[0].Current == nil || states[0].Current.ID != ids[4] {
		t.Fatalf("états %+v, %v", states, err)
	}
	// Une référence retirée garde son historique ; une référence retirée sans instantané
	// disparaît.
	f.exec(t, `UPDATE tracked_refs SET removed_at = now() WHERE id = $1`, f.main)
	f.exec(t, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name, removed_at)
		VALUES ($1, $2, $3, 'repo', 'tag', 'v1', now())`, f.org, newID(), f.repo)
	f.exec(t, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'dev')`,
		f.org, newID(), f.repo)
	states, err = svc.RefStates(ctx, f.org, f.repo)
	if err != nil || len(states) != 2 || states[0].Name != "dev" || states[0].Current != nil || !states[1].Removed {
		t.Errorf("états après retrait %+v, %v", states, err)
	}

	err = f.pool.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
		cur, err := CurrentByRef(ctx, tx, []uuid.UUID{f.main, f.hostRef, newID()})
		if err != nil {
			return err
		}
		if len(cur) != 2 || cur[f.main].Commit != commit(5) || cur[f.hostRef].Commit != "" {
			t.Errorf("courants %+v", cur)
		}
		if empty, err := CurrentByRef(ctx, tx, nil); err != nil || len(empty) != 0 {
			t.Errorf("sans référence : %v, %v", empty, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	last, err := svc.LastSnapshots(ctx, f.org, []uuid.UUID{f.repo, f.host, newID()})
	if err != nil || len(last) != 2 || !last[f.host].Equal(t0) {
		t.Errorf("derniers instantanés %v, %v", last, err)
	}
	if empty, err := svc.LastSnapshots(ctx, f.org, nil); err != nil || len(empty) != 0 {
		t.Errorf("sans projet : %v", err)
	}
}

func TestReadItems(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	f := newFixture(t, tdb.App)
	svc := NewService(tdb.App)
	ctx := context.Background()
	raw := sbom.RawDocument{Components: []sbom.RawComponent{
		{PURL: "pkg:deb/debian/openssl@3.0.14?arch=amd64", Name: "openssl", Licenses: []string{"Apache-2.0"},
			CPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*"}},
		{PURL: "pkg:npm/jquery@3.4.1", Name: "jquery", Origin: "ia", Confidence: "0.82", Model: "m", Scope: "required",
			Evidence: []byte(`{"occurrences":[{"location":"a.js"}]}`)},
		{Name: "libfoo_100%", Version: "1.2"},
	}}
	res := f.store(t, f.repoRecord(commit(1), sbom.Normalize(raw).Components, time.Now()))
	all, types, err := svc.Items(ctx, f.org, res.SetID, ItemFilter{}, "", 10)
	if err != nil || len(all.Items) != 3 || len(types) != 3 {
		t.Fatalf("composants %+v, types %v, %v", all, types, err)
	}
	jq := all.Items[2]
	if jq.Name != "jquery" || jq.Origin != sbom.OriginIA || jq.Confidence == nil || *jq.Confidence != 0.82 || jq.Model != "m" ||
		jq.Scope != sbom.ScopeRequired || len(jq.Evidence) == 0 {
		t.Errorf("composant IA %+v", jq)
	}
	if ssl := all.Items[0]; ssl.Name != "openssl" || len(ssl.CPEs) != 1 || len(ssl.Licenses) != 1 || ssl.Confidence != nil || ssl.Evidence != nil {
		t.Errorf("composant Syft %+v", ssl)
	}
	for _, tc := range []struct {
		f    ItemFilter
		want int
	}{
		{ItemFilter{Query: "SSL"}, 1},
		{ItemFilter{Query: "pkg:npm"}, 1},
		{ItemFilter{Query: "_100%"}, 1},
		{ItemFilter{Query: "%"}, 1},
		{ItemFilter{Origin: sbom.OriginIA}, 1},
		{ItemFilter{Origin: sbom.OriginSyft}, 2},
		{ItemFilter{Type: "deb"}, 1},
		{ItemFilter{WeakOnly: true}, 1},
		{ItemFilter{Query: "absent"}, 0},
	} {
		page, _, err := svc.Items(ctx, f.org, res.SetID, tc.f, "", 10)
		if err != nil || len(page.Items) != tc.want {
			t.Errorf("filtre %+v : %d composants, %v", tc.f, len(page.Items), err)
		}
	}
	first, _, err := svc.Items(ctx, f.org, res.SetID, ItemFilter{}, "", 2)
	if err != nil || first.NextCursor == "" {
		t.Fatal(err)
	}
	next, _, err := svc.Items(ctx, f.org, res.SetID, ItemFilter{}, first.NextCursor, 2)
	if err != nil || len(next.Items) != 1 || next.NextCursor != "" {
		t.Errorf("page suivante %+v, %v", next, err)
	}
	if _, _, err := svc.Items(ctx, f.org, res.SetID, ItemFilter{}, "", ItemPageMax+1); err == nil {
		t.Error("taille de page non bornée")
	}
	if _, _, err := svc.Items(ctx, f.org, res.SetID, ItemFilter{}, "illisible", 2); err == nil {
		t.Error("curseur illisible accepté")
	}
}

// Isolement : une organisation ne lit ni les instantanés ni les composants d'une autre,
// même en connaissant leurs identifiants.
func TestReadIsolation(t *testing.T) {
	t.Parallel()
	tdb := newDB(t)
	a, b := newFixture(t, tdb.App), newFixture(t, tdb.App)
	svc := NewService(tdb.App)
	ctx := context.Background()
	res := a.store(t, a.repoRecord(commit(1), components(3, "1.0.0"), time.Now()))
	if _, err := svc.Snapshot(ctx, b.org, a.repo, res.SnapshotID); !errors.Is(err, ErrNotFound) {
		t.Errorf("instantané de A lu par B : %v", err)
	}
	page, err := svc.Snapshots(ctx, b.org, a.repo, uuid.Nil, "", 10)
	if err != nil || len(page.Items) != 0 {
		t.Errorf("instantanés de A listés par B : %d, %v", len(page.Items), err)
	}
	items, types, err := svc.Items(ctx, b.org, res.SetID, ItemFilter{}, "", 10)
	if err != nil || len(items.Items) != 0 || len(types) != 0 {
		t.Errorf("composants de A lus par B : %d, %v", len(items.Items), err)
	}
	states, err := svc.RefStates(ctx, b.org, a.repo)
	if err != nil || len(states) != 0 {
		t.Errorf("références de A lues par B : %v", states)
	}
}
