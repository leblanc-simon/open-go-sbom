//go:build integration

package db_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// orgTable est une table d'organisation du harnais d'isolement SQL : sa colonne
// d'organisation et l'insertion d'une ligne pour l'organisation déclarée (userID est un
// compte global créé pour l'occasion). Un lot qui crée une table d'organisation l'ajoute
// ici, dans l'ordre de ses dépendances : TestOrgTablesAreAllCovered échoue sinon.
type orgTable struct {
	name string
	col  string
	seed func(ctx context.Context, tx *db.OrgTx, userID int64) error
}

var orgTables = []orgTable{
	{"organizations", "id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language)
			VALUES ($1::uuid, 'o-' || right($1::uuid::text, 12), 'Organisation', 'fr')`, tx.OrgID())
		return err
	}},
	{"org_memberships", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, 'admin')`,
			tx.OrgID(), userID)
		return err
	}},
	{"audit_events", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (org_id, id, actor_user_id, action)
			VALUES ($1, $2, $3, 'member.added')`, tx.OrgID(), uuid.Must(uuid.NewV7()), userID)
		return err
	}},
}

// errAbort annule volontairement une transaction de test.
var errAbort = errors.New("annulation volontaire")

func seedOrg(t *testing.T, tdb *dbtest.DB, org tenant.OrgID, email string) {
	t.Helper()
	ctx := context.Background()
	var userID int64
	if err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email).Scan(&userID)
	}); err != nil {
		t.Fatal(err)
	}
	if err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		for _, tbl := range orgTables {
			if err := tbl.seed(ctx, tx, userID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOrgTablesAreAllCovered : toute table d'organisation du schéma figure au harnais.
func TestOrgTablesAreAllCovered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	rows, err := tdb.App.DB().QueryContext(ctx, `
		SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		   AND (c.relname = 'organizations' OR EXISTS (
		         SELECT 1 FROM pg_attribute a
		          WHERE a.attrelid = c.oid AND a.attname = 'org_id' AND a.attnotnull AND NOT a.attisdropped))
		 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	var want []string
	for _, tbl := range orgTables {
		want = append(want, tbl.name)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("tables d'organisation du schéma %v, harnais %v : ajouter la table à orgTables", got, want)
	}
}

// TestRLSOnEveryOrgTable : dans InOrg(A), des requêtes sans filtre ne lisent ni n'écrivent
// rien de B ; hors InOrg, elles échouent.
func TestRLSOnEveryOrgTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	a, b := newOrg(t), newOrg(t)
	seedOrg(t, tdb, a, "a@example.org")
	seedOrg(t, tdb, b, "b@example.org")

	for _, tbl := range orgTables {
		t.Run(tbl.name, func(t *testing.T) {
			// Lecture : seules les lignes de A, et aucune de B même en la nommant.
			err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
				var total, ofB int
				if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE `+tbl.col+` = $1) FROM `+tbl.name, b).
					Scan(&total, &ofB); err != nil {
					return err
				}
				if total != 1 || ofB != 0 {
					t.Errorf("A voit %d lignes dont %d de B", total, ofB)
				}
				return nil
			}, db.ReadOnly())
			if err != nil {
				t.Fatal(err)
			}

			// Écriture sans filtre : seules les lignes de A sont touchées (transaction
			// annulée ensuite).
			_ = tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
				res, err := tx.ExecContext(ctx, `UPDATE `+tbl.name+` SET `+tbl.col+` = `+tbl.col)
				if err != nil {
					t.Fatalf("mise à jour sans filtre : %v", err)
				}
				if n, _ := res.RowsAffected(); n != 1 {
					t.Errorf("mise à jour sans filtre : %d lignes, attendu 1", n)
				}
				return errAbort
			})

			// Déplacer une ligne de A vers B est refusé.
			err = tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
				_, err := tx.ExecContext(ctx, `UPDATE `+tbl.name+` SET `+tbl.col+` = $1`, b)
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "row-level security") {
				t.Errorf("déplacement vers B : err = %v", err)
			}

			// Hors InOrg : échec franc, jamais zéro ligne.
			var n int
			if err := tdb.App.DB().QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n); err == nil {
				t.Errorf("hors InOrg : %d lignes sans erreur", n)
			}
			if err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
				return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n)
			}); err == nil {
				t.Errorf("dans InTx : %d lignes sans erreur", n)
			}

			// Les lignes de B sont intactes.
			if err := tdb.App.InOrg(ctx, b, func(tx *db.OrgTx) error {
				return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n)
			}); err != nil || n != 1 {
				t.Errorf("B : %d lignes, %v", n, err)
			}
		})
	}
}
