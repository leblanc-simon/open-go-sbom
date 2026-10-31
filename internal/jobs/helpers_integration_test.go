//go:build integration

package jobs

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// fakeClock est une horloge que le test avance. Elle part une heure après l'heure réelle :
// les jobs mis en file par Enqueue (horloge du système) sont donc déjà échus pour elle.
// Elle est arrondie à la microseconde, précision de timestamptz, pour comparer exactement
// les dates relues.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Now().Add(time.Hour).Truncate(time.Microsecond)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// fastOptions : workers réactifs pour les tests.
func fastOptions(o RunnerOptions) RunnerOptions {
	if o.PollInterval == 0 {
		o.PollInterval = 10 * time.Millisecond
	}
	if o.MaintenanceInterval == 0 {
		o.MaintenanceInterval = time.Hour
	}
	return o
}

// startRunner démarre un runner et l'arrête en fin de test.
func startRunner(t *testing.T, pool *db.Pool, o RunnerOptions, register func(r *Runner)) *Runner {
	t.Helper()
	r := NewRunner(pool, fastOptions(o))
	register(r)
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = r.Stop(ctx)
	})
	return r
}

func mustRegister(t *testing.T, r *Runner, kind string, h HandlerFunc, opts ...KindOption) {
	t.Helper()
	if err := r.Register(kind, h, opts...); err != nil {
		t.Fatal(err)
	}
}

func enqueue(t testing.TB, pool *db.Pool, j Job) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		var err error
		id, err = Enqueue(context.Background(), tx, j)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// newOrg crée une organisation : jobs.org_id la référence (migration 008).
func newOrg(t testing.TB, pool *db.Pool) tenant.OrgID {
	t.Helper()
	o, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	err = pool.InOrg(context.Background(), o, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO organizations (id, slug, name, default_language)
			VALUES ($1::uuid, 'o-' || right($1::uuid::text, 12), 'Organisation', 'fr')`, o)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// waitFor attend que cond soit vraie, au plus timeout.
func waitFor(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type jobRow struct {
	Status      string
	Attempts    int
	Priority    int
	RunAt       time.Time
	LockedUntil sql.NullTime
	LeaseToken  uuid.NullUUID
	LastError   sql.NullString
	FinishedAt  sql.NullTime
}

func readJob(t testing.TB, pool *db.Pool, id uuid.UUID) jobRow {
	t.Helper()
	var r jobRow
	err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT status, attempts, priority, run_at, locked_until, lease_token, last_error, finished_at
			FROM jobs WHERE id = $1`, id).
			Scan(&r.Status, &r.Attempts, &r.Priority, &r.RunAt, &r.LockedUntil, &r.LeaseToken, &r.LastError, &r.FinishedAt)
	})
	if err != nil {
		t.Fatalf("lecture du job %s : %v", id, err)
	}
	return r
}

func status(t testing.TB, pool *db.Pool, id uuid.UUID) string {
	t.Helper()
	return readJob(t, pool, id).Status
}

func count(t testing.TB, pool *db.Pool, where string, args ...any) int {
	t.Helper()
	var n int
	err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		return tx.QueryRowContext(context.Background(), "SELECT count(*) FROM jobs WHERE "+where, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func execSQL(t testing.TB, pool *db.Pool, query string, args ...any) {
	t.Helper()
	err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
