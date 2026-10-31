//go:build integration

package benchdata

import (
	"context"
	"testing"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/tenant"
)

func TestAddSearchFixtures(t *testing.T) {
	ctx := context.Background()
	d := dbtest.New(t)
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(ctx, d.App, org, "bench", Params{Projects: 40, Links: 4000, Components: 1009, Vulnerabilities: 50, VulnerableEvery: 10}); err != nil {
		t.Fatal(err)
	}
	if err := AddSearchFixtures(ctx, d.App, org); err != nil {
		t.Fatal(err)
	}
	var versions, links, hashed int
	err = d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM components WHERE purl_base = 'pkg:npm/lodash'),
			(SELECT count(*) FROM component_set_items i JOIN components c ON c.org_id = i.org_id AND c.id = i.component_id WHERE c.purl_base = 'pkg:npm/lodash'),
			(SELECT count(*) FROM components WHERE hashes @> ARRAY[$1])`, SearchHash(7)).Scan(&versions, &links, &hashed)
	})
	if err != nil {
		t.Fatal(err)
	}
	if versions != SearchVersions || links != 40 || hashed != 1 {
		t.Fatalf("%d versions, %d liens, %d composants à l'empreinte", versions, links, hashed)
	}
}
