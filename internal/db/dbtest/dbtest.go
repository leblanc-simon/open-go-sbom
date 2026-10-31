// Package dbtest fournit à chaque test d'intégration une base PostgreSQL jetable.
//
// À partir de LOTOR_TEST_DATABASE_DSN (connexion d'administration, au format URL), New
// crée une base, un rôle propriétaire et un rôle d'exécution, tous nommés avec un suffixe
// aléatoire, applique les migrations avec le propriétaire et renvoie le pool du rôle
// d'exécution. Tout est supprimé à la fin du test. Des tests de lots différents peuvent
// donc tourner en parallèle sur le même serveur.
//
//	//go:build integration
//
//	func TestSomething(t *testing.T) {
//		t.Parallel()
//		tdb := dbtest.New(t)
//		err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error { … })
//	}
//
// Sans la variable, le test échoue avec un message explicite : les tests d'intégration ne
// tournent qu'avec l'étiquette integration (make test-integration).
package dbtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"leblanc.io/lotor/internal/db"
)

// EnvDSN est la variable d'environnement de la connexion d'administration.
const EnvDSN = "LOTOR_TEST_DATABASE_DSN"

// setupTimeout borne la création et la suppression d'une base de test.
const setupTimeout = 30 * time.Second

// DB est une base de test et ses deux rôles.
type DB struct {
	Name      string
	OwnerRole string
	AppRole   string
	// OwnerDSN et AppDSN se connectent à la base de test avec chaque rôle.
	OwnerDSN string
	AppDSN   string
	// App est le pool du rôle d'exécution, fermé en fin de test.
	App *db.Pool

	admin *url.URL
}

type options struct {
	migrate bool
}

// Option ajuste New.
type Option func(*options)

// WithoutMigrations laisse la base vide (tests de l'exécuteur de migrations).
func WithoutMigrations() Option { return func(o *options) { o.migrate = false } }

// AdminDSN renvoie la connexion d'administration, ou fait échouer le test si elle manque.
func AdminDSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv(EnvDSN)
	if dsn == "" {
		t.Fatalf("%s n'est pas défini : les tests d'intégration ont besoin d'une connexion d'administration "+
			"PostgreSQL (par exemple postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable, "+
			"cf. deploy/compose.yaml et make test-integration)", EnvDSN)
	}
	return dsn
}

// New crée une base jetable et ses rôles, et applique les migrations (sauf
// WithoutMigrations).
func New(t testing.TB, opts ...Option) *DB {
	t.Helper()
	o := options{migrate: true}
	for _, opt := range opts {
		opt(&o)
	}
	admin, err := url.Parse(AdminDSN(t))
	if err != nil || (admin.Scheme != "postgres" && admin.Scheme != "postgresql") {
		t.Fatalf("%s doit être une URL postgres://…", EnvDSN)
	}

	suffix := randomHex(t, 6)
	d := &DB{
		Name:      "lotor_t_" + suffix,
		OwnerRole: "lotor_t_" + suffix + "_owner",
		AppRole:   "lotor_t_" + suffix + "_app",
		admin:     admin,
	}
	ownerPwd, appPwd := randomHex(t, 16), randomHex(t, 16)

	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	// Le nettoyage est enregistré avant la création : il tourne même si elle échoue à
	// mi-chemin, et après la fermeture des pools (t.Cleanup est LIFO).
	t.Cleanup(func() { d.drop(t) })
	d.adminExec(ctx, t,
		// BYPASSRLS : les fonctions de crossorg en dépendent (migration 005, ADR 0012).
		fmt.Sprintf("CREATE ROLE %s LOGIN BYPASSRLS PASSWORD '%s'", ident(d.OwnerRole), ownerPwd),
		fmt.Sprintf("CREATE ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'", ident(d.AppRole), appPwd),
		fmt.Sprintf("CREATE DATABASE %s OWNER %s TEMPLATE template0 ENCODING 'UTF8'", ident(d.Name), ident(d.OwnerRole)),
		fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM PUBLIC", ident(d.Name)),
		fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", ident(d.Name), ident(d.AppRole)),
	)
	d.OwnerDSN = d.dsn(d.OwnerRole, ownerPwd, d.Name)
	d.AppDSN = d.dsn(d.AppRole, appPwd, d.Name)

	if o.migrate {
		owner := d.Owner(t)
		if _, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: d.AppRole}); err != nil {
			t.Fatalf("dbtest: migrations : %v", err)
		}
	}
	d.App = db.NewPool(d.open(t, d.AppDSN, 10))
	return d
}

// Owner ouvre un pool du rôle propriétaire (deux connexions, comme l'exige Migrate),
// fermé en fin de test.
func (d *DB) Owner(t testing.TB) *sql.DB {
	t.Helper()
	return d.open(t, d.OwnerDSN, 2)
}

// NewRole crée un rôle jetable de connexion avec les attributs donnés (« SUPERUSER »,
// « BYPASSRLS »…), autorisé à se connecter à la base de test, et renvoie son DSN. Le
// rôle est supprimé en fin de test.
func (d *DB) NewRole(t testing.TB, attrs string) (role, dsn string) {
	t.Helper()
	role = d.Name + "_" + randomHex(t, 3)
	pwd := randomHex(t, 16)
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
		defer cancel()
		// Les privilèges reçus dans la base de test sont retirés avant la suppression.
		d.adminExecIn(ctx, t, d.Name, "DROP OWNED BY "+ident(role))
		d.adminExec(ctx, t, "DROP ROLE IF EXISTS "+ident(role))
	})
	d.adminExec(ctx, t,
		fmt.Sprintf("CREATE ROLE %s LOGIN %s PASSWORD '%s'", ident(role), attrs, pwd),
		fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", ident(d.Name), ident(role)),
	)
	return role, d.dsn(role, pwd, d.Name)
}

// AdminExec exécute des instructions d'administration dans la base de test (connexion
// d'administration), par exemple pour accorder un rôle.
func (d *DB) AdminExec(t testing.TB, stmts ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	d.adminExecIn(ctx, t, d.Name, stmts...)
}

func (d *DB) open(t testing.TB, dsn string, maxConns int) *sql.DB {
	t.Helper()
	pool, err := db.Open(dsn, db.PoolConfig{MaxOpenConns: maxConns, MaxIdleConns: maxConns, ApplicationName: "lotor-test"})
	if err != nil {
		t.Fatalf("dbtest: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

func (d *DB) dsn(user, password, dbname string) string {
	u := *d.admin
	u.User = url.UserPassword(user, password)
	u.Path = "/" + dbname
	return u.String()
}

func (d *DB) adminExec(ctx context.Context, t testing.TB, stmts ...string) {
	t.Helper()
	d.adminExecIn(ctx, t, strings.TrimPrefix(d.admin.Path, "/"), stmts...)
}

func (d *DB) adminExecIn(ctx context.Context, t testing.TB, dbname string, stmts ...string) {
	t.Helper()
	u := *d.admin
	u.Path = "/" + dbname
	pool, err := db.Open(u.String(), db.PoolConfig{MaxOpenConns: 1})
	if err != nil {
		t.Fatalf("dbtest: %v", err)
	}
	defer pool.Close()
	for _, s := range stmts {
		if _, err := pool.ExecContext(ctx, s); err != nil {
			t.Fatalf("dbtest: %s : %v", redact(s), err)
		}
	}
}

func (d *DB) drop(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	d.adminExec(ctx, t,
		fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", ident(d.Name)),
		"DROP ROLE IF EXISTS "+ident(d.AppRole),
		"DROP ROLE IF EXISTS "+ident(d.OwnerRole),
	)
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

// redact retire le mot de passe d'une instruction CREATE ROLE avant de l'afficher.
func redact(stmt string) string {
	if i := strings.Index(stmt, "PASSWORD"); i >= 0 {
		return stmt[:i] + "PASSWORD …"
	}
	return stmt
}

func randomHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("dbtest: aléa : %v", err)
	}
	return hex.EncodeToString(b)
}
