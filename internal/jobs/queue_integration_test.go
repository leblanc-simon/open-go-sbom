//go:build integration

package jobs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/tenant"
)

// Test de charge court : 10 000 jobs, trois runners de huit workers, dix organisations,
// un type plafonné et un type libre ; aucun doublon, aucune perte, plafond tenu.
func TestLoadTenThousandJobs(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	const total, orgCount, limit = 10000, 10, 3
	orgs := make([]tenant.OrgID, orgCount)
	for i := range orgs {
		orgs[i] = newOrg(t, tdb.App)
	}
	err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		for i := range total {
			kind := "test.light"
			if i%2 == 0 {
				kind = "test.heavy"
			}
			if _, err := Enqueue(ctx, tx, Job{Kind: kind, OrgID: orgs[i%orgCount], Priority: i % 5, Payload: map[string]int{"n": i}}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	runs := make(map[uuid.UUID]int, total)
	var heavyRunning [orgCount]atomic.Int32
	var heavyMax [orgCount]atomic.Int32
	var done atomic.Int32
	orgIndex := map[tenant.OrgID]int{}
	for i, o := range orgs {
		orgIndex[o] = i
	}
	record := func(e Execution) {
		mu.Lock()
		runs[e.ID]++
		mu.Unlock()
		done.Add(1)
	}
	heavy := func(_ context.Context, e Execution) error {
		i := orgIndex[e.OrgID]
		n := heavyRunning[i].Add(1)
		for {
			m := heavyMax[i].Load()
			if n <= m || heavyMax[i].CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		heavyRunning[i].Add(-1)
		record(e)
		return nil
	}
	light := func(_ context.Context, e Execution) error { record(e); return nil }
	begin := time.Now()
	for range 3 {
		startRunner(t, tdb.App, RunnerOptions{Concurrency: 8}, func(r *Runner) {
			mustRegister(t, r, "test.heavy", heavy, WithOrgLimit(limit))
			mustRegister(t, r, "test.light", light)
		})
	}
	waitFor(t, 5*time.Minute, "10 000 jobs", func() bool { return done.Load() >= total })
	elapsed := time.Since(begin)
	waitFor(t, 10*time.Second, "statuts done", func() bool { return count(t, tdb.App, "status = 'done'") == total })
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != total {
		t.Fatalf("%d jobs distincts exécutés, attendu %d", len(runs), total)
	}
	for id, n := range runs {
		if n != 1 {
			t.Fatalf("job %s exécuté %d fois", id, n)
		}
	}
	for i := range orgs {
		if m := heavyMax[i].Load(); m > limit {
			t.Fatalf("organisation %d : %d jobs plafonnés simultanés, plafond %d", i, m, limit)
		}
	}
	t.Logf("10 000 jobs en %s (%.0f jobs/s), 3 runners × 8 workers", elapsed.Round(time.Millisecond), total/elapsed.Seconds())
}

// Le bail est renouvelé tant que le handler tourne : un second runner ne prend pas le
// job, même au-delà de la durée initiale du bail.
//
// Le handler dure plus de deux baux. Un bail de 1,5 s (renouvelé toutes les 500 ms)
// laisse passer un renouvellement retardé d'une seconde sur une machine chargée ; avec
// 300 ms, un retard de 200 ms suffisait à perdre le bail (échec en CI, T11).
func TestLeaseIsRenewedWhileHandlerRuns(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	var runs atomic.Int32
	h := func(context.Context, Execution) error {
		runs.Add(1)
		time.Sleep(4 * time.Second)
		return nil
	}
	for range 2 {
		startRunner(t, tdb.App, RunnerOptions{Lease: 1500 * time.Millisecond}, func(r *Runner) {
			mustRegister(t, r, "test.long", h)
		})
	}
	id := enqueue(t, tdb.App, Job{Kind: "test.long"})
	waitFor(t, 20*time.Second, "job terminé", func() bool { return status(t, tdb.App, id) == "done" })
	if r := readJob(t, tdb.App, id); runs.Load() != 1 || r.Attempts != 1 {
		t.Fatalf("%d exécutions, %d tentatives : bail non renouvelé", runs.Load(), r.Attempts)
	}
}

// Un bail perdu (repris ailleurs) annule le handler et son résultat est ignoré.
//
// L'autre worker est simulé comme un vrai : il pose son propre jeton et son propre bail.
// Le bail de 3 s laisse au renouvellement (toutes les secondes) le temps de passer sur une
// machine chargée. Avec un bail de 300 ms et le seul jeton changé, ce runner reprenait le
// job dont il venait de laisser expirer le bail, avant la vérification (échec en CI, T11).
func TestLostLeaseCancelsHandler(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	m, err := NewMetrics(prometheus.NewRegistry(), tdb.App, nil)
	if err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	started, canceled := make(chan struct{}), make(chan struct{})
	startRunner(t, tdb.App, RunnerOptions{Lease: 3 * time.Second, Metrics: m}, func(r *Runner) {
		mustRegister(t, r, "test.lost", func(ctx context.Context, _ Execution) error {
			if runs.Add(1) > 1 {
				return errors.New("job repris par le runner qui a perdu son bail")
			}
			close(started)
			<-ctx.Done()
			close(canceled)
			return nil
		})
	})
	id := enqueue(t, tdb.App, Job{Kind: "test.lost"})
	<-started
	// Un autre worker a repris le job : nouveau jeton, nouveau bail.
	other, until := uuid.New(), time.Now().Add(time.Hour).Truncate(time.Microsecond)
	execSQL(t, tdb.App, `UPDATE jobs SET lease_token = $2, locked_until = $3 WHERE id = $1`, id, other, until)
	select {
	case <-canceled:
	case <-time.After(10 * time.Second):
		t.Fatal("handler non annulé après la perte du bail")
	}
	// Le runner a fini de traiter la perte : plus rien ne peut écrire après ce point.
	waitFor(t, 10*time.Second, "issue « bail perdu »", func() bool {
		return testutil.ToFloat64(m.runs.WithLabelValues("test.lost", outcomeLost)) == 1
	})
	r := readJob(t, tdb.App, id)
	if r.Status != "running" || r.LeaseToken.UUID != other || !r.LockedUntil.Time.Equal(until) || r.Attempts != 1 || r.LastError.Valid {
		t.Fatalf("job %+v : le résultat d'un bail perdu a été enregistré", r)
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("%d exécutions, attendu 1", n)
	}
}

// Erreur permanente : dead dès la première tentative. Panique : un échec comme un autre.
// Délai du type : le handler est annulé et la tentative échoue.
func TestPermanentErrorPanicAndTimeout(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	startRunner(t, tdb.App, RunnerOptions{}, func(r *Runner) {
		mustRegister(t, r, "test.permanent", func(context.Context, Execution) error {
			return Permanent(errors.New("charge invalide"))
		})
		mustRegister(t, r, "test.panic", func(context.Context, Execution) error { panic("boum") })
		mustRegister(t, r, "test.slow", func(ctx context.Context, _ Execution) error {
			<-ctx.Done()
			return ctx.Err()
		}, WithTimeout(50*time.Millisecond))
		mustRegister(t, r, "test.decode", func(_ context.Context, e Execution) error {
			var p struct{ Ref string }
			return e.Decode(&p)
		})
	})
	perm := enqueue(t, tdb.App, Job{Kind: "test.permanent", MaxAttempts: 5})
	pan := enqueue(t, tdb.App, Job{Kind: "test.panic", MaxAttempts: 5})
	slow := enqueue(t, tdb.App, Job{Kind: "test.slow", MaxAttempts: 5})
	bad := enqueue(t, tdb.App, Job{Kind: "test.decode", Payload: map[string]string{"unknown": "x"}})
	waitFor(t, 10*time.Second, "erreur permanente", func() bool { return status(t, tdb.App, perm) == "dead" })
	if r := readJob(t, tdb.App, perm); r.Attempts != 1 || r.LastError.String != "charge invalide" {
		t.Fatalf("permanente : %+v", r)
	}
	waitFor(t, 10*time.Second, "panique", func() bool { return readJob(t, tdb.App, pan).Attempts == 1 && status(t, tdb.App, pan) == "pending" })
	if r := readJob(t, tdb.App, pan); !strings.Contains(r.LastError.String, "panique dans le handler de test.panic : boum") {
		t.Fatalf("panique : %q", r.LastError.String)
	}
	waitFor(t, 10*time.Second, "délai", func() bool { return readJob(t, tdb.App, slow).Attempts == 1 && status(t, tdb.App, slow) == "pending" })
	if r := readJob(t, tdb.App, slow); r.LastError.String != context.DeadlineExceeded.Error() {
		t.Fatalf("délai : %q", r.LastError.String)
	}
	waitFor(t, 10*time.Second, "charge illisible", func() bool { return status(t, tdb.App, bad) == "dead" })
}

// Maintenance : un job dont le bail a expiré pendant sa dernière tentative passe dead ;
// les jobs terminés au-delà de la rétention sont purgés, pas les autres.
func TestMaintenanceReapsAndPurges(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	clock := newFakeClock()
	r := NewRunner(tdb.App, RunnerOptions{Clock: clock, Retention: 24 * time.Hour})
	now := clock.Now()

	exhausted := enqueue(t, tdb.App, Job{Kind: "test.m", MaxAttempts: 2})
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'running', attempts = 2, lease_token = $2, locked_until = $3 WHERE id = $1`,
		exhausted, uuid.New(), now.Add(-time.Second))
	alive := enqueue(t, tdb.App, Job{Kind: "test.m", MaxAttempts: 2})
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'running', attempts = 2, lease_token = $2, locked_until = $3 WHERE id = $1`,
		alive, uuid.New(), now.Add(time.Minute))
	old := enqueue(t, tdb.App, Job{Kind: "test.m"})
	recent := enqueue(t, tdb.App, Job{Kind: "test.m"})
	oldDead := enqueue(t, tdb.App, Job{Kind: "test.m"})
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'done', finished_at = $2 WHERE id = $1`, old, now.Add(-25*time.Hour))
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'done', finished_at = $2 WHERE id = $1`, recent, now.Add(-23*time.Hour))
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'dead', finished_at = $2 WHERE id = $1`, oldDead, now.Add(-48*time.Hour))

	if n, err := r.reapExhausted(ctx); err != nil || n != 1 {
		t.Fatalf("reapExhausted : %d, %v", n, err)
	}
	if row := readJob(t, tdb.App, exhausted); row.Status != "dead" || !strings.Contains(row.LastError.String, "bail expiré") {
		t.Fatalf("job épuisé : %+v", row)
	}
	if s := status(t, tdb.App, alive); s != "running" {
		t.Fatalf("job au bail valide : %s", s)
	}
	if n, err := r.purge(ctx); err != nil || n != 1 {
		t.Fatalf("purge : %d, %v", n, err)
	}
	if count(t, tdb.App, "id = $1", old) != 0 || count(t, tdb.App, "id IN ($1, $2)", recent, oldDead) != 2 {
		t.Fatal("purge : mauvais jobs supprimés")
	}
}

// Un job épuisé dont le bail expire n'est pas repris par la prise.
func TestExhaustedExpiredJobIsNotClaimed(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	clock := newFakeClock()
	id := enqueue(t, tdb.App, Job{Kind: "test.x", MaxAttempts: 1})
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'running', attempts = 1, lease_token = $2, locked_until = $3 WHERE id = $1`,
		id, uuid.New(), clock.Now().Add(-time.Second))
	r := NewRunner(tdb.App, RunnerOptions{Clock: clock})
	mustRegister(t, r, "test.x", func(context.Context, Execution) error { return nil })
	r.kindNames = []string{"test.x"}
	c, err := r.claim(context.Background(), "w")
	if err != nil || c != nil {
		t.Fatalf("claim : %+v, %v", c, err)
	}
}

func TestEnqueueInOrgTransaction(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	org := newOrg(t, tdb.App)
	var id uuid.UUID
	err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		id, err = Enqueue(ctx, tx, Job{Kind: "test.org"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, tdb.App, "id = $1 AND org_id = $2", id, org); n != 1 {
		t.Fatal("l'organisation de la transaction n'a pas été reprise")
	}
	err = tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		_, err := Enqueue(ctx, tx, Job{Kind: "test.org", OrgID: newOrg(t, tdb.App)})
		return err
	})
	if !errors.Is(err, ErrOrgMismatch) {
		t.Fatalf("err = %v, attendu ErrOrgMismatch", err)
	}
	err = tdb.App.InTx(ctx, func(tx *db.Tx) error {
		_, err := Enqueue(ctx, tx, Job{Kind: "Invalide"})
		return err
	})
	if !errors.Is(err, ErrInvalidJob) {
		t.Fatalf("err = %v, attendu ErrInvalidJob", err)
	}

	// Le handler reçoit l'organisation et peut ouvrir InOrg avec.
	got := make(chan tenant.OrgID, 1)
	startRunner(t, tdb.App, RunnerOptions{}, func(r *Runner) {
		mustRegister(t, r, "test.org", func(ctx context.Context, e Execution) error {
			if err := tdb.App.InOrg(ctx, e.OrgID, func(*db.OrgTx) error { return nil }); err != nil {
				return err
			}
			got <- e.OrgID
			return nil
		})
	})
	select {
	case o := <-got:
		if o != org {
			t.Fatalf("organisation %s, attendu %s", o, org)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("job non exécuté")
	}
}

func TestAdminDeadJobs(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)
	var dead []uuid.UUID
	for i := range 5 {
		id := enqueue(t, tdb.App, Job{Kind: "test.dead", UniqueKey: "k" + string(rune('a'+i))})
		execSQL(t, tdb.App, `UPDATE jobs SET status = 'dead', attempts = 10, last_error = 'raté', finished_at = $2 WHERE id = $1`,
			id, base.Add(time.Duration(i)*time.Minute))
		dead = append(dead, id)
	}
	pending := enqueue(t, tdb.App, Job{Kind: "test.dead"})

	inTx := func(fn func(tx *db.Tx) error) error { return tdb.App.InTx(ctx, fn) }
	var pages [][]DeadJob
	cursor := ""
	for {
		var page pagination.Page[DeadJob]
		if err := inTx(func(tx *db.Tx) (err error) { page, err = ListDead(ctx, tx, cursor, 2); return }); err != nil {
			t.Fatal(err)
		}
		pages = append(pages, page.Items)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(pages) != 3 || pages[0][0].ID != dead[4] || pages[2][0].ID != dead[0] || pages[0][0].LastError != "raté" {
		t.Fatalf("pages : %+v", pages)
	}
	if err := inTx(func(tx *db.Tx) error { _, err := ListDead(ctx, tx, "", 0); return err }); err == nil {
		t.Fatal("limite 0 acceptée")
	}
	if err := inTx(func(tx *db.Tx) error { _, err := ListDead(ctx, tx, "illisible", 10); return err }); !errors.Is(err, pagination.ErrInvalidCursor) {
		t.Fatalf("curseur illisible : %v", err)
	}

	if err := inTx(func(tx *db.Tx) error { return Retry(ctx, tx, dead[0]) }); err != nil {
		t.Fatal(err)
	}
	if r := readJob(t, tdb.App, dead[0]); r.Status != "pending" || r.Attempts != 0 || r.FinishedAt.Valid {
		t.Fatalf("relance : %+v", r)
	}
	// Relance alors qu'un jumeau attend : le jumeau fera le travail, le mort disparaît.
	enqueue(t, tdb.App, Job{Kind: "test.dead", UniqueKey: "kb"})
	err := inTx(func(tx *db.Tx) error {
		if err := Retry(ctx, tx, dead[1]); err != nil {
			return err
		}
		// La transaction de l'appelant reste utilisable.
		_, err := tx.ExecContext(ctx, `SELECT 1`)
		return err
	})
	if err != nil || count(t, tdb.App, "id = $1", dead[1]) != 0 {
		t.Fatalf("relance avec jumeau : %v", err)
	}
	if err := inTx(func(tx *db.Tx) error { return Discard(ctx, tx, dead[2]) }); err != nil || count(t, tdb.App, "id = $1", dead[2]) != 0 {
		t.Fatalf("suppression : %v", err)
	}
	for _, id := range []uuid.UUID{pending, dead[2], uuid.New()} {
		if err := inTx(func(tx *db.Tx) error { return Retry(ctx, tx, id) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("relance de %s : %v, attendu ErrNotFound", id, err)
		}
		if err := inTx(func(tx *db.Tx) error { return Discard(ctx, tx, id) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("suppression de %s : %v, attendu ErrNotFound", id, err)
		}
	}
}

// CountJobs, GetDead et Active servent l'écran d'administration et l'import de la base.
func TestAdminCountsAndLookups(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	q := tdb.App.DB()
	enqueue(t, tdb.App, Job{Kind: "test.a", UniqueKey: "x"})
	running := enqueue(t, tdb.App, Job{Kind: "test.a", UniqueKey: "y"})
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'running', lease_token = $2, locked_until = now() + interval '1 hour' WHERE id = $1`,
		running, uuid.New())
	dead := enqueue(t, tdb.App, Job{Kind: "test.a", UniqueKey: "z"})
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'dead', attempts = 3, last_error = 'raté', finished_at = now() WHERE id = $1`, dead)
	done := enqueue(t, tdb.App, Job{Kind: "test.a"})
	execSQL(t, tdb.App, `UPDATE jobs SET status = 'done', finished_at = now() WHERE id = $1`, done)

	if c, err := CountJobs(ctx, q); err != nil || c != (Counts{Pending: 1, Running: 1, Dead: 1}) {
		t.Fatalf("comptes : %+v, %v", c, err)
	}
	for key, want := range map[string]bool{"x": true, "y": true, "z": false, "absente": false} {
		if got, err := Active(ctx, q, "test.a", key); err != nil || got != want {
			t.Errorf("Active(%s) = %v, %v ; attendu %v", key, got, err, want)
		}
	}
	if ok, err := Active(ctx, q, "test.b", "x"); err != nil || ok {
		t.Errorf("Active d'un autre type : %v, %v", ok, err)
	}
	err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		d, err := GetDead(ctx, tx, dead)
		if err != nil || d.ID != dead || d.Kind != "test.a" || d.UniqueKey != "z" || d.Attempts != 3 || d.LastError != "raté" {
			t.Errorf("GetDead : %+v, %v", d, err)
		}
		for _, id := range []uuid.UUID{running, done, uuid.New()} {
			if _, err := GetDead(ctx, tx, id); !errors.Is(err, ErrNotFound) {
				t.Errorf("GetDead(%s) : %v, attendu ErrNotFound", id, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg, tdb.App, nil)
	if err != nil {
		t.Fatal(err)
	}
	failed := make(chan struct{})
	var once sync.Once
	startRunner(t, tdb.App, RunnerOptions{Metrics: m}, func(r *Runner) {
		mustRegister(t, r, "test.ok", func(context.Context, Execution) error { return nil })
		mustRegister(t, r, "test.ko", func(context.Context, Execution) error {
			once.Do(func() { close(failed) })
			return errors.New("raté")
		})
	})
	ok := enqueue(t, tdb.App, Job{Kind: "test.ok"})
	enqueue(t, tdb.App, Job{Kind: "test.ko"})
	enqueue(t, tdb.App, Job{Kind: "test.unknown"})
	waitFor(t, 10*time.Second, "job terminé", func() bool { return status(t, tdb.App, ok) == "done" })
	<-failed
	waitFor(t, 10*time.Second, "échec compté", func() bool {
		return testutil.ToFloat64(m.runs.WithLabelValues("test.ko", outcomeRetry)) == 1
	})
	if v := testutil.ToFloat64(m.runs.WithLabelValues("test.ok", outcomeDone)); v != 1 {
		t.Fatalf("runs done = %v", v)
	}
	if n := testutil.CollectAndCount(reg, "lotor_job_duration_seconds"); n != 2 {
		t.Fatalf("%d séries de durée", n)
	}
	want := `
# HELP lotor_jobs Jobs in the queue by kind and status (pending, running, dead), shared by all instances.
# TYPE lotor_jobs gauge
lotor_jobs{kind="test.ko",status="pending"} 1
lotor_jobs{kind="test.unknown",status="pending"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "lotor_jobs"); err != nil {
		t.Fatal(err)
	}
}

// L'inscription d'une échéance garde son prochain point, sauf si sa grille change ; Run
// prend les échéances dues et s'arrête à l'annulation.
func TestSchedulerSyncAndRun(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	clock := newFakeClock()
	next := func() time.Time {
		var n time.Time
		err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT next_run_at FROM schedules WHERE name = 'test.daily'`).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	daily := Schedule{Name: "test.daily", Every: 24 * time.Hour, Offset: 3 * time.Hour, Job: Job{Kind: "test.daily"}}
	s := NewScheduler(tdb.App, SchedulerOptions{Clock: clock})
	if err := s.Register(daily); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(daily); err == nil {
		t.Fatal("échéance enregistrée deux fois")
	}
	if err := s.sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := next(); !got.Equal(daily.lastPoint(clock.Now())) || got.Hour() != 3 {
		t.Fatalf("nouvelle échéance : %s, attendu %s (due tout de suite, à 03:00)", got, daily.lastPoint(clock.Now()))
	}
	if n, err := s.tick(ctx); err != nil || n != 1 {
		t.Fatalf("tick : %d, %v", n, err)
	}
	if n := count(t, tdb.App, "kind = 'test.daily' AND unique_key = 'schedule:test.daily'"); n != 1 {
		t.Fatal("job de l'échéance absent ou sans clé par défaut")
	}
	// Redémarrage, même grille : le prochain point est conservé.
	s2 := NewScheduler(tdb.App, SchedulerOptions{Clock: clock})
	_ = s2.Register(daily)
	if err := s2.sync(ctx); err != nil || !next().Equal(daily.nextPoint(clock.Now())) {
		t.Fatalf("prochain point perdu au redémarrage : %s (%v)", next(), err)
	}
	// Nouvelle grille : premier point de celle-ci.
	changed := daily
	changed.Every, changed.Offset = 12*time.Hour, 0
	s3 := NewScheduler(tdb.App, SchedulerOptions{Clock: clock})
	_ = s3.Register(changed)
	if err := s3.sync(ctx); err != nil || !next().Equal(changed.nextPoint(clock.Now())) {
		t.Fatalf("grille modifiée : %s, attendu %s (%v)", next(), changed.nextPoint(clock.Now()), err)
	}

	// Run : prend l'échéance due, puis s'arrête à l'annulation.
	clock.Set(changed.nextPoint(clock.Now()))
	runCtx, cancel := context.WithCancel(ctx)
	s4 := NewScheduler(tdb.App, SchedulerOptions{Clock: clock, Interval: 10 * time.Millisecond})
	_ = s4.Register(changed)
	errc := make(chan error, 1)
	go func() { errc <- s4.Run(runCtx) }()
	waitFor(t, 10*time.Second, "échéance prise par Run", func() bool {
		var n int
		_ = tdb.App.InTx(ctx, func(tx *db.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM schedules WHERE name = 'test.daily' AND last_run_at = $1`,
				clock.Now()).Scan(&n)
		})
		return n == 1
	})
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := s4.Run(ctx); err == nil {
		t.Fatal("second Run accepté")
	}
	if err := s4.Register(Schedule{Name: "test.late", Every: time.Hour, Job: Job{Kind: "test.late"}}); err == nil {
		t.Fatal("échéance enregistrée après Run")
	}
}
