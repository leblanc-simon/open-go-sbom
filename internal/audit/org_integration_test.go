//go:build integration

package audit_test

import (
	"context"
	"testing"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/tenant"
)

func TestRecordAndListOrg(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	var userID int64
	if err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash) VALUES ('a@example.org', 'x') RETURNING id`).Scan(&userID)
	}); err != nil {
		t.Fatal(err)
	}
	orgs := make([]tenant.OrgID, 2)
	for i := range orgs {
		orgs[i], _ = tenant.NewOrgID()
		err := tdb.App.InOrg(ctx, orgs[i], func(tx *db.OrgTx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, 'O', 'fr')`,
				tx.OrgID(), []string{"a", "b"}[i]); err != nil {
				return err
			}
			for range i + 1 {
				if err := audit.RecordOrg(ctx, tx, audit.Actor{UserID: userID, Email: "a@example.org"},
					audit.Event{Action: audit.MemberAdded, TargetLabel: "x"}); err != nil {
					return err
				}
			}
			return audit.RecordOrg(ctx, tx, audit.System, audit.Event{Action: "nope.nope"})
		})
		if err == nil {
			t.Fatal("action inconnue acceptée")
		}
		// L'échec annule la transaction : on recommence sans l'action fautive.
		if err := tdb.App.InOrg(ctx, orgs[i], func(tx *db.OrgTx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, 'O', 'fr')`,
				tx.OrgID(), []string{"a", "b"}[i]); err != nil {
				return err
			}
			for range i + 1 {
				if err := audit.RecordOrg(ctx, tx, audit.Actor{UserID: userID, Email: "a@example.org"},
					audit.Event{Action: audit.MemberAdded, TargetLabel: "x"}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i, org := range orgs {
		err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
			p, err := audit.ListOrg(ctx, tx, "", 10)
			if err != nil {
				return err
			}
			if len(p.Items) != i+1 || p.Items[0].ActorUserID != userID {
				t.Errorf("organisation %d : %+v", i, p.Items)
			}
			return nil
		}, db.ReadOnly())
		if err != nil {
			t.Fatal(err)
		}
	}
}
