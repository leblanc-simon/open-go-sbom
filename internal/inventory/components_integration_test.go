//go:build integration

package inventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// TestComponentUsage : un composant et l'usage courant de sa famille ; références
// retirées et projets archivés exclus ; RLS.
func TestComponentUsage(t *testing.T) {
	d := newDB(t)
	f := newFixture(t, d.App)
	ctx := context.Background()
	now := time.Now()
	f.store(t, f.repoRecord(commit(1), components(3, "1.0.0"), now.Add(-time.Hour)))
	f.store(t, f.hostRecord(components(2, "2.0.0"), now.Add(-time.Minute)))
	var id uuid.UUID
	if err := d.App.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT id FROM components WHERE purl = 'pkg:npm/paquet-00000@1.0.0'`).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	s := NewService(d.App)
	c, usage, err := s.Component(ctx, f.org, tenant.AllTeams(), id)
	if err != nil || c.PURLBase != "pkg:npm/paquet-00000" || c.Version != "1.0.0" || len(c.CPEs) != 1 {
		t.Fatalf("composant %+v, %v", c, err)
	}
	if len(usage) != 2 || usage[0].Version != "2.0.0" || usage[0].RefKind != "host" || usage[1].Version != "1.0.0" ||
		usage[1].Commit != commit(1) || usage[1].ProjectSlug != "depot" || len(usage[1].Licenses) != 1 {
		t.Fatalf("usages %+v", usage)
	}
	f.exec(t, `UPDATE projects SET archived_at = now() WHERE id = $1`, f.host)
	f.exec(t, `UPDATE tracked_refs SET removed_at = now() WHERE id = $1`, f.main)
	if _, usage, err := s.Component(ctx, f.org, tenant.AllTeams(), id); err != nil || len(usage) != 0 {
		t.Fatalf("usages après retrait et archivage : %+v, %v", usage, err)
	}
	if _, _, err := s.Component(ctx, f.org, tenant.AllTeams(), uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("composant inconnu : %v", err)
	}
	other := newFixture(t, d.App)
	if _, _, err := s.Component(ctx, other.org, tenant.AllTeams(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("composant d'une autre organisation : %v", err)
	}
}
