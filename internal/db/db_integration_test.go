//go:build integration

package db_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/db/migrations"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// withMigrations ajoute des migrations de test à celles du projet.
func withMigrations(t *testing.T, extra map[string]string) fstest.MapFS {
	t.Helper()
	fsys := fstest.MapFS{}
	all, err := db.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		fsys[m.Name] = &fstest.MapFile{Data: []byte(m.SQL)}
	}
	for name, body := range extra {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func countMigrations(t *testing.T, q db.Querier) int {
	t.Helper()
	var n int
	if err := q.QueryRowContext(context.Background(), "SELECT count(*) FROM "+db.MigrationsTable).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrateFreshDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	owner := tdb.Owner(t)
	all, _ := db.LoadMigrations(migrations.FS)

	if err := db.VerifySchema(ctx, tdb.App.DB(), nil); err == nil {
		t.Fatal("VerifySchema sur une base vide : pas d'erreur")
	}
	applied, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: tdb.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != len(all) {
		t.Fatalf("appliquées = %d, attendu %d", len(applied), len(all))
	}
	if err := db.VerifySchema(ctx, tdb.App.DB(), nil); err != nil {
		t.Fatalf("VerifySchema avec le rôle d'exécution : %v", err)
	}
	again, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: tdb.AppRole})
	if err != nil || len(again) != 0 {
		t.Fatalf("seconde migration : %v, %v", again, err)
	}
	if err := db.CheckRuntimeRole(ctx, tdb.App.DB()); err != nil {
		t.Fatalf("rôle d'exécution refusé : %v", err)
	}
}

func TestMigrateConcurrentInstancesMigrateOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	all, _ := db.LoadMigrations(migrations.FS)

	const instances = 6
	owners := make([]*sql.DB, instances)
	for i := range owners {
		owners[i] = tdb.Owner(t)
	}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total int
		errs  []error
	)
	for _, owner := range owners {
		wg.Go(func() {
			applied, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: tdb.AppRole})
			mu.Lock()
			defer mu.Unlock()
			total += len(applied)
			if err != nil {
				errs = append(errs, err)
			}
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	if total != len(all) {
		t.Fatalf("migrations appliquées au total = %d, attendu %d (une seule fois chacune)", total, len(all))
	}
	if n := countMigrations(t, tdb.App.DB()); n != len(all) {
		t.Fatalf("lignes de suivi = %d", n)
	}
}

func TestMigrateRefusesAlteredMigration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	altered := withMigrations(t, nil)
	altered["001_init.sql"].Data = append(altered["001_init.sql"].Data, []byte("\n-- modifiée\n")...)

	_, err := db.Migrate(ctx, tdb.Owner(t), db.MigrateOptions{AppRole: tdb.AppRole, Migrations: altered})
	if !errors.Is(err, db.ErrChecksumMismatch) || !strings.Contains(err.Error(), "001_init.sql") {
		t.Fatalf("err = %v, attendu ErrChecksumMismatch", err)
	}
	if err := db.VerifySchema(ctx, tdb.App.DB(), altered); !errors.Is(err, db.ErrChecksumMismatch) {
		t.Fatalf("VerifySchema : err = %v", err)
	}
}

func TestMigrateRefusesNewerDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	owner := tdb.Owner(t)
	newer := withMigrations(t, map[string]string{"002_future.sql": "SELECT 1"})
	if _, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: tdb.AppRole, Migrations: newer}); err != nil {
		t.Fatal(err)
	}
	_, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: tdb.AppRole})
	if !errors.Is(err, db.ErrUnknownMigration) || !strings.Contains(err.Error(), "002_future.sql") {
		t.Fatalf("err = %v, attendu ErrUnknownMigration", err)
	}
}

func TestMigrateIsAllOrNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	broken := withMigrations(t, map[string]string{
		"002_table.sql":  "CREATE TABLE t_ok (id int)",
		"003_broken.sql": "CREATE TABLE t_broken (id int, oops)",
	})
	if _, err := db.Migrate(ctx, tdb.Owner(t), db.MigrateOptions{AppRole: tdb.AppRole, Migrations: broken}); err == nil {
		t.Fatal("migration invalide acceptée")
	}
	if n := countMigrations(t, tdb.App.DB()); n != 0 {
		t.Fatalf("%d migrations enregistrées après l'échec, attendu 0", n)
	}
	var exists bool
	if err := tdb.App.DB().QueryRow("SELECT to_regclass('t_ok') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatalf("t_ok subsiste après l'échec (%v)", err)
	}
}

func TestMigrateRequiresTwoConnections(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	pool, err := db.Open(tdb.OwnerDSN, db.PoolConfig{MaxOpenConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := db.Migrate(context.Background(), pool, db.MigrateOptions{AppRole: tdb.AppRole}); err == nil {
		t.Fatal("pool d'une connexion accepté")
	}
}

func TestMigrateRunsStepsUnderLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	var ran []string
	step := func(name string) db.Step {
		return db.Step{Name: name, Run: func(ctx context.Context, owner *sql.DB) error {
			// Le verrou est tenu par une autre connexion : une écriture sur la table de
			// suivi depuis le pool attendrait. Une lecture, elle, ne bloque pas.
			var n int
			if err := owner.QueryRowContext(ctx, "SELECT count(*) FROM "+db.MigrationsTable).Scan(&n); err != nil {
				return err
			}
			ran = append(ran, name)
			return nil
		}}
	}
	_, err := db.Migrate(ctx, tdb.Owner(t), db.MigrateOptions{
		AppRole: tdb.AppRole,
		Before:  []db.Step{step("authx"), step("mfax")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ran, ",") != "authx,mfax" {
		t.Fatalf("étapes = %v", ran)
	}
	failing := db.Step{Name: "authx", Run: func(context.Context, *sql.DB) error { return errors.New("boom") }}
	_, err = db.Migrate(ctx, tdb.Owner(t), db.MigrateOptions{AppRole: tdb.AppRole, Before: []db.Step{failing}})
	if err == nil || !strings.Contains(err.Error(), "authx") {
		t.Fatalf("err = %v", err)
	}
}

func TestMigrateRefusesUnprotectedOrgTable(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		sql     string
		wantErr bool
	}{
		"sans RLS": {"CREATE TABLE things (org_id uuid NOT NULL, v text)", true},
		"RLS standard": {`CREATE TABLE things (org_id uuid NOT NULL, v text);
			CALL ogsbom_enforce_org_rls('things')`, false},
		"RLS non forcée": {`CREATE TABLE things (org_id uuid NOT NULL, v text);
			CALL ogsbom_enforce_org_rls('things');
			ALTER TABLE things NO FORCE ROW LEVEL SECURITY`, true},
		"politique permissive en plus": {`CREATE TABLE things (org_id uuid NOT NULL, v text);
			CALL ogsbom_enforce_org_rls('things');
			CREATE POLICY open ON things USING (true)`, true},
		"politique restrictive en plus": {`CREATE TABLE things (org_id uuid NOT NULL, v text);
			CALL ogsbom_enforce_org_rls('things');
			CREATE POLICY not_empty ON things AS RESTRICTIVE USING (v <> '')`, false},
		"organizations sans RLS": {"CREATE TABLE organizations (id uuid PRIMARY KEY)", true},
		"organizations protégée": {`CREATE TABLE organizations (id uuid PRIMARY KEY);
			CALL ogsbom_enforce_org_rls('organizations', 'id')`, false},
		"table globale à org_id facultatif": {"CREATE TABLE jobs (org_id uuid, kind text)", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tdb := dbtest.New(t, dbtest.WithoutMigrations())
			fsys := withMigrations(t, map[string]string{"002_test.sql": c.sql})
			_, err := db.Migrate(context.Background(), tdb.Owner(t), db.MigrateOptions{AppRole: tdb.AppRole, Migrations: fsys})
			if c.wantErr != errors.Is(err, db.ErrUnprotectedOrgTable) {
				t.Fatalf("err = %v, attendu en erreur : %v", err, c.wantErr)
			}
		})
	}
}

func TestDefaultPrivilegesOfRuntimeRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	owner := tdb.Owner(t)
	for _, s := range []string{
		"CREATE TABLE later (id bigserial PRIMARY KEY, v text)",
		"CREATE FUNCTION later_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'",
	} {
		if _, err := owner.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	app := tdb.App.DB()
	for _, s := range []string{
		"INSERT INTO later (v) VALUES ('a')",
		"UPDATE later SET v = 'b'",
		"SELECT count(*) FROM later",
		"SELECT later_fn()",
		"DELETE FROM later",
	} {
		if _, err := app.ExecContext(ctx, s); err != nil {
			t.Errorf("%s : %v", s, err)
		}
	}
	for _, s := range []string{
		"TRUNCATE later",
		"CREATE TABLE mine (id int)",
		"ALTER TABLE later ADD COLUMN w text",
		"DROP TABLE later",
		"INSERT INTO " + db.MigrationsTable + " (version, name, checksum) VALUES (99, 'x', 'y')",
		"CREATE TABLE z (org_id uuid NOT NULL); CALL ogsbom_enforce_org_rls('z')",
	} {
		if _, err := app.ExecContext(ctx, s); err == nil {
			t.Errorf("%s : accepté pour le rôle d'exécution", s)
		}
	}
	// Un rôle sans droit particulier n'exécute pas les fonctions du propriétaire.
	_, otherDSN := tdb.NewRole(t, "")
	other, err := db.Open(otherDSN, db.PoolConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.ExecContext(ctx, "SELECT later_fn()"); err == nil {
		t.Error("un rôle tiers exécute une fonction du propriétaire")
	}
}

func TestCheckRuntimeRoleRefusesPowerfulRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)

	member, memberDSN := tdb.NewRole(t, "NOSUPERUSER NOBYPASSRLS")
	tdb.AdminExec(t, "GRANT "+quote(tdb.OwnerRole)+" TO "+quote(member))
	_, superDSN := tdb.NewRole(t, "SUPERUSER")
	_, bypassDSN := tdb.NewRole(t, "BYPASSRLS")

	cases := map[string]struct {
		dsn  string
		want string
	}{
		"superutilisateur":       {superDSN, "superutilisateur"},
		"BYPASSRLS":              {bypassDSN, "BYPASSRLS"},
		"propriétaire":           {tdb.OwnerDSN, "propriétaire"},
		"membre du propriétaire": {memberDSN, "propriétaire"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			pool, err := db.Open(c.dsn, db.PoolConfig{})
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			err = db.CheckRuntimeRole(ctx, pool)
			if !errors.Is(err, db.ErrUnsafeRole) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, attendu ErrUnsafeRole (%s)", err, c.want)
			}
		})
	}
}

func quote(s string) string { return `"` + s + `"` }

// rlsDB crée une base avec une table d'organisation de test sous la politique standard.
func rlsDB(t *testing.T) *dbtest.DB {
	t.Helper()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	fsys := withMigrations(t, map[string]string{"002_probe.sql": `
		CREATE TABLE probe (org_id uuid NOT NULL, v text NOT NULL);
		CALL ogsbom_enforce_org_rls('probe');`})
	if _, err := db.Migrate(context.Background(), tdb.Owner(t), db.MigrateOptions{AppRole: tdb.AppRole, Migrations: fsys}); err != nil {
		t.Fatal(err)
	}
	return tdb
}

func newOrg(t *testing.T) tenant.OrgID {
	t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	return org
}

func TestRLSIsolatesOrganizations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := rlsDB(t)
	a, b := newOrg(t), newOrg(t)
	insert := func(org tenant.OrgID, v string) error {
		return tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO probe (org_id, v) VALUES ($1, $2)", tx.OrgID(), v)
			return err
		})
	}
	for _, r := range []struct {
		org tenant.OrgID
		v   string
	}{{a, "a1"}, {a, "a2"}, {b, "b1"}} {
		if err := insert(r.org, r.v); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("lecture sans filtre", func(t *testing.T) {
		err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
			rows, err := tx.QueryContext(ctx, "SELECT v FROM probe ORDER BY v")
			if err != nil {
				return err
			}
			defer rows.Close()
			var got []string
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err != nil {
					return err
				}
				got = append(got, v)
			}
			if strings.Join(got, ",") != "a1,a2" {
				t.Errorf("A voit %v", got)
			}
			return rows.Err()
		}, db.ReadOnly())
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("écriture pour une autre organisation", func(t *testing.T) {
		err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO probe (org_id, v) VALUES ($1, 'intrus')", b)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("insertion pour B depuis A : err = %v", err)
		}
	})

	t.Run("modification et suppression sans filtre", func(t *testing.T) {
		err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
			if _, err := tx.ExecContext(ctx, "UPDATE probe SET v = v || '!'"); err != nil {
				return err
			}
			// Déplacer une ligne de A vers B est aussi refusé (WITH CHECK).
			if _, err := tx.ExecContext(ctx, "UPDATE probe SET org_id = $1", b); err == nil {
				t.Error("déplacement d'une ligne vers B accepté")
			}
			return nil
		})
		if err == nil {
			t.Fatal("la transaction aurait dû échouer après le refus")
		}
		err = tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
			res, err := tx.ExecContext(ctx, "DELETE FROM probe")
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 2 {
				t.Errorf("A supprime %d lignes, attendu 2", n)
			}
			return errors.New("annulation volontaire")
		})
		if err == nil {
			t.Fatal("annulation attendue")
		}
		var n int
		err = tdb.App.InOrg(ctx, b, func(tx *db.OrgTx) error {
			return tx.QueryRowContext(ctx, "SELECT count(*) FROM probe WHERE v = 'b1'").Scan(&n)
		})
		if err != nil || n != 1 {
			t.Fatalf("ligne de B : %d, %v", n, err)
		}
	})

	t.Run("hors InOrg, la requête échoue", func(t *testing.T) {
		// Une connexion neuve (paramètre jamais défini) et une connexion réutilisée après
		// InOrg (paramètre revenu à '') : les deux échouent, aucune ne renvoie zéro ligne.
		pool, err := db.Open(tdb.AppDSN, db.PoolConfig{MaxOpenConns: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		p := db.NewPool(pool)
		var n int
		if err := pool.QueryRowContext(ctx, "SELECT count(*) FROM probe").Scan(&n); err == nil {
			t.Errorf("connexion neuve : %d lignes sans erreur", n)
		}
		if err := p.InOrg(ctx, a, func(tx *db.OrgTx) error {
			return tx.QueryRowContext(ctx, "SELECT count(*) FROM probe").Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRowContext(ctx, "SELECT count(*) FROM probe").Scan(&n); err == nil {
			t.Errorf("connexion réutilisée : %d lignes sans erreur", n)
		}
		if err := p.InTx(ctx, func(tx *db.Tx) error {
			return tx.QueryRowContext(ctx, "SELECT count(*) FROM probe").Scan(&n)
		}); err == nil {
			t.Errorf("InTx : %d lignes sans erreur", n)
		}
	})
}

func TestInTxCommitRollbackAndPanic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	if _, err := tdb.Owner(t).ExecContext(ctx, "CREATE TABLE g (v text)"); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := tdb.App.DB().QueryRowContext(ctx, "SELECT count(*) FROM g").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	insert := func(tx *db.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO g VALUES ('x')")
		return err
	}
	if err := tdb.App.InTx(ctx, insert); err != nil || count() != 1 {
		t.Fatalf("validation : %v, %d", err, count())
	}
	wantErr := errors.New("refus")
	err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		if err := insert(tx); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) || count() != 1 {
		t.Fatalf("annulation : %v, %d", err, count())
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panique avalée")
			}
		}()
		_ = tdb.App.InTx(ctx, func(tx *db.Tx) error {
			_ = insert(tx)
			panic("boom")
		})
	}()
	if count() != 1 {
		t.Fatalf("après panique : %d lignes", count())
	}
	if err := tdb.App.InTx(ctx, insert, db.ReadOnly()); err == nil {
		t.Fatal("écriture acceptée en lecture seule")
	}
}

// TestPgxArrays vérifie l'encodage des tableaux par pgx à travers database/sql, sans
// lib/pq (ADR 0002).
func TestPgxArrays(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	app := tdb.App.DB()

	texts := []string{"a", "b,c", `d"e`, ""}
	var gotTexts []string
	if err := app.QueryRowContext(ctx, "SELECT $1::text[]", texts).Scan(db.Array(&gotTexts)); err != nil {
		t.Fatalf("text[] : %v", err)
	}
	if strings.Join(gotTexts, "|") != strings.Join(texts, "|") {
		t.Fatalf("text[] = %q", gotTexts)
	}

	ints := []int64{1, -2, 1 << 40}
	var gotInts []int64
	if err := app.QueryRowContext(ctx, "SELECT $1::bigint[]", ints).Scan(db.Array(&gotInts)); err != nil {
		t.Fatalf("bigint[] : %v", err)
	}
	if len(gotInts) != 3 || gotInts[2] != 1<<40 {
		t.Fatalf("bigint[] = %v", gotInts)
	}

	ids := []uuid.UUID{uuid.New(), uuid.New()}
	var n int
	if err := app.QueryRowContext(ctx, "SELECT cardinality($1::uuid[])", ids).Scan(&n); err != nil || n != 2 {
		t.Fatalf("uuid[] : %d, %v", n, err)
	}
	var gotIDs []uuid.UUID
	if err := app.QueryRowContext(ctx, "SELECT $1::uuid[]", ids).Scan(db.Array(&gotIDs)); err != nil {
		t.Fatalf("uuid[] relu : %v", err)
	}
	if len(gotIDs) != 2 || gotIDs[0] != ids[0] {
		t.Fatalf("uuid[] = %v", gotIDs)
	}
	var hit bool
	if err := app.QueryRowContext(ctx, "SELECT $1 = ANY($2::text[])", "b,c", texts).Scan(&hit); err != nil || !hit {
		t.Fatalf("= ANY : %v, %v", hit, err)
	}
}

func startOptions(tdb *dbtest.DB) db.StartOptions {
	return db.StartOptions{
		DSN: tdb.AppDSN, Pool: db.PoolConfig{MaxOpenConns: 4, ApplicationName: "ogsbom-test"},
		StartupTimeout: 10 * time.Second, MigrationDSN: tdb.OwnerDSN, MigrationMaxConns: 2,
	}
}

func TestStartMigratesAndChecks(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	pool, err := db.Start(context.Background(), startOptions(tdb))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := db.VerifySchema(context.Background(), pool.DB(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStartWithoutMigrationRequiresUpToDateSchema(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	o := startOptions(tdb)
	o.MigrationDSN = ""
	if _, err := db.Start(context.Background(), o); err == nil || !strings.Contains(err.Error(), "migration.dsn") {
		t.Fatalf("schéma vide sans migration : err = %v", err)
	}
	migrated := dbtest.New(t)
	o = startOptions(migrated)
	o.MigrationDSN = ""
	pool, err := db.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("schéma à jour sans migration : %v", err)
	}
	pool.Close()
}

// TestStartRefusesPowerfulRuntimeRole : le serveur refuse de démarrer si le rôle
// d'exécution est superutilisateur, BYPASSRLS ou propriétaire des tables.
func TestStartRefusesPowerfulRuntimeRole(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	_, superDSN := tdb.NewRole(t, "SUPERUSER")
	_, bypassDSN := tdb.NewRole(t, "BYPASSRLS")
	for name, dsn := range map[string]string{"superutilisateur": superDSN, "BYPASSRLS": bypassDSN, "propriétaire": tdb.OwnerDSN} {
		t.Run(name, func(t *testing.T) {
			o := startOptions(tdb)
			o.DSN, o.MigrationDSN = dsn, ""
			if _, err := db.Start(context.Background(), o); !errors.Is(err, db.ErrUnsafeRole) {
				t.Fatalf("err = %v, attendu ErrUnsafeRole", err)
			}
		})
	}
}

func TestStartGivesUpOnUnreachableDatabase(t *testing.T) {
	t.Parallel()
	o := db.StartOptions{DSN: "postgres://u:p@127.0.0.1:1/x?connect_timeout=1", StartupTimeout: 300 * time.Millisecond}
	if _, err := db.Start(context.Background(), o); err == nil {
		t.Fatal("base injoignable acceptée")
	}
}
