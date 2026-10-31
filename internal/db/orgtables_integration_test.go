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
	{"agents", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'host', 'srv-01')`,
			tx.OrgID(), seedID(tx, "agent"))
		return err
	}},
	{"projects", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO projects (org_id, id, kind, slug, name, agent_id)
			VALUES ($1, $2, 'host', 'srv-01', 'srv-01', $3)`, tx.OrgID(), seedID(tx, "project"), seedID(tx, "agent"))
		return err
	}},
	{"tracked_refs", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
			VALUES ($1, $2, $3, 'host', 'host', 'srv-01')`, tx.OrgID(), seedID(tx, "ref"), seedID(tx, "project"))
		return err
	}},
	{"sbom_blobs", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content)
			VALUES ($1, $2, sha256('{}'::bytea), 2, 1, '\x00'::bytea)`, tx.OrgID(), seedID(tx, "blob"))
		return err
	}},
	{"components", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO components (org_id, id, purl, purl_base, type, name, version)
			VALUES ($1, $2, 'pkg:npm/a@1', 'pkg:npm/a', 'npm', 'a', '1')`, tx.OrgID(), seedID(tx, "component"))
		return err
	}},
	{"component_sets", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
			VALUES ($1, $2, sha256('set'::bytea), 1, 1, 0, 0)`, tx.OrgID(), seedID(tx, "set"))
		return err
	}},
	{"component_set_items", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO component_set_items (org_id, set_id, component_id, origin)
			VALUES ($1, $2, $3, 'syft')`, tx.OrgID(), seedID(tx, "set"), seedID(tx, "component"))
		return err
	}},
	{"snapshots", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO snapshots (org_id, id, project_id, ref_id, agent_id, scanned_at, last_scanned_at,
			blob_id, set_id, format, spec_version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, now(), now(), $6, $7, 'cyclonedx', '1.6', now(), now())`,
			tx.OrgID(), seedID(tx, "snapshot"), seedID(tx, "project"), seedID(tx, "ref"), seedID(tx, "agent"),
			seedID(tx, "blob"), seedID(tx, "set"))
		return err
	}},
	{"ref_current", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO ref_current (org_id, ref_id, project_id, snapshot_id, set_id, updated_at)
			VALUES ($1, $2, $3, $4, $5, now())`,
			tx.OrgID(), seedID(tx, "ref"), seedID(tx, "project"), seedID(tx, "snapshot"), seedID(tx, "set"))
		return err
	}},
	{"ingestions", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO ingestions (org_id, id, agent_id, project_id, ref_id, scanned_at, blob_id,
			status, snapshot_id, outcome, received_at, finished_at)
			VALUES ($1, $2, $3, $4, $5, now(), $6, 'done', $7, 'created', now(), now())`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), seedID(tx, "agent"), seedID(tx, "project"), seedID(tx, "ref"),
			seedID(tx, "blob"), seedID(tx, "snapshot"))
		return err
	}},
	{"findings", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		// Le catalogue est global : la fiche est partagée par les deux organisations.
		if _, err := tx.ExecContext(ctx, `INSERT INTO vulnerabilities (id, source_rank, severity, vulndb_built, updated_at)
			VALUES ('CVE-2021-44228', 0, 'critical', now(), now()) ON CONFLICT DO NOTHING`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status,
			severity, risk, fix_state, match_type, first_seen_at, last_seen_at, snapshot_id, vulndb_archive, vulndb_built, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'CVE-2021-44228', 'open', 'critical', 99, 'fixed', 'exact-direct', now(), now(), $6, $7, now(), now())`,
			tx.OrgID(), seedID(tx, "finding"), seedID(tx, "project"), seedID(tx, "ref"), seedID(tx, "component"),
			seedID(tx, "snapshot"), uuid.Must(uuid.NewV7()))
		return err
	}},
	{"finding_events", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO finding_events (org_id, finding_id, at, kind, snapshot_id, vulndb_archive)
			VALUES ($1, $2, now(), 'opened', $3, $4)`, tx.OrgID(), seedID(tx, "finding"), seedID(tx, "snapshot"), uuid.Must(uuid.NewV7()))
		return err
	}},
	{"ref_analyses", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO ref_analyses (org_id, ref_id, project_id, set_id, snapshot_id, vulndb_archive,
			vulndb_built, analyzed_at, match_count, unmatched_count)
			VALUES ($1, $2, $3, $4, $5, $6, now(), now(), 1, 0)`,
			tx.OrgID(), seedID(tx, "ref"), seedID(tx, "project"), seedID(tx, "set"), seedID(tx, "snapshot"), uuid.Must(uuid.NewV7()))
		return err
	}},
	{"agent_tokens", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO agent_tokens (org_id, id, agent_id, public_id, secret_hash, name)
			VALUES ($1, $2, $3, $4, sha256('a'::bytea), 'initial')`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), seedID(tx, "agent"), publicID(tx, "a"))
		return err
	}},
	{"enrollment_tokens", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens (org_id, id, public_id, secret_hash, name, expires_at, max_uses)
			VALUES ($1, $2, $3, sha256('e'::bytea), 'parc', now() + interval '1 day', 5)`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), publicID(tx, "e"))
		return err
	}},
	{"org_daily_stats", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO org_daily_stats (org_id, day, open_critical, open_high, open_medium, open_low,
			open_negligible, open_unknown, open_kev, kev_vulns, projects, silent_agents, fixed_critical, fixed_high, fixed_medium,
			fixed_low, fixed_negligible, fixed_unknown, recorded_at)
			VALUES ($1, current_date, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, now())`, tx.OrgID())
		return err
	}},
	{"project_daily_stats", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO project_daily_stats (org_id, project_id, day, open_critical, open_high,
			open_medium, open_low, open_negligible, open_unknown, open_kev, recorded_at)
			VALUES ($1, $2, current_date, 1, 0, 0, 0, 0, 0, 1, now())`, tx.OrgID(), seedID(tx, "project"))
		return err
	}},
}

// seedID dérive un identifiant stable de l'organisation et d'un nom, pour relier les
// lignes du harnais entre elles.
func seedID(tx *db.OrgTx, name string) uuid.UUID {
	return uuid.NewSHA1(tx.OrgID().UUID(), []byte(name))
}

// publicID dérive un identifiant public de jeton unique par organisation (26 caractères
// base32 minuscules).
func publicID(tx *db.OrgTx, name string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	id := seedID(tx, "token-"+name)
	out := make([]byte, 26)
	for i := range out {
		out[i] = alphabet[int(id[i%16]+byte(i))%32]
	}
	return string(out)
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

// appendOnly sont les tables d'organisation en ajout seul pour le rôle d'exécution
// (journal d'audit, migration 015) : ni UPDATE ni DELETE.
var appendOnly = map[string]bool{"audit_events": true}

// assertAppendOnly : la table refuse UPDATE et DELETE au rôle d'exécution, et la RLS
// refuse d'y ajouter une ligne de B depuis A ; les lignes de B restent intactes.
func assertAppendOnly(t *testing.T, tdb *dbtest.DB, a, b tenant.OrgID, tbl orgTable) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{`UPDATE ` + tbl.name + ` SET ` + tbl.col + ` = ` + tbl.col, `DELETE FROM ` + tbl.name} {
		err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
			_, err := tx.ExecContext(ctx, q)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s : err = %v, attendu un refus de droit", q, err)
		}
	}
	err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (org_id, id, action) VALUES ($1, gen_random_uuid(), 'member.added')`, b)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("ajout d'une ligne de B depuis A : err = %v", err)
	}
	var n int
	if err := tdb.App.InOrg(ctx, b, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n)
	}); err != nil || n != 1 {
		t.Errorf("B : %d lignes, %v", n, err)
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

			if appendOnly[tbl.name] {
				assertAppendOnly(t, tdb, a, b, tbl)
				return
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
