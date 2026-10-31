package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// maxErrorLen borne la dernière erreur conservée.
const maxErrorLen = 4000

// orgLimitLockClass est la première clé des verrous consultatifs de transaction qui
// sérialisent la prise des jobs plafonnés d'un même (type, organisation).
const orgLimitLockClass = 0x6a6f6273 // « jobs »

// purgeBatch borne chaque suppression de jobs terminés.
const purgeBatch = 1000

// errSaturated annule une prise : l'organisation a atteint son plafond pour ce type.
var errSaturated = errors.New("jobs: plafond atteint")

// La prise choisit le job le plus prioritaire, puis le plus ancien. Les couples (type,
// organisation) au plafond sont exclus d'emblée ; $5/$6 excluent ceux que la vérification
// sous verrou a trouvés saturés. Elle se fait en deux requêtes, pour que celle des jobs
// en attente parcoure l'index jobs_pending dans l'ordre et s'arrête au premier job
// admissible : d'abord les jobs dont le bail a expiré (worker disparu) sans avoir épuisé
// leurs tentatives, déjà commencés, puis les jobs en attente échus.
const (
	claimHead = `
WITH caps AS (
	SELECT * FROM unnest($3::text[], $4::int[]) AS c(kind, cap)
), saturated AS (
	SELECT r.kind, r.org_id
	FROM jobs r JOIN caps c ON c.kind = r.kind
	WHERE r.status = 'running' AND r.locked_until > $2 AND r.org_id IS NOT NULL
	GROUP BY r.kind, r.org_id, c.cap
	HAVING count(*) >= c.cap
)
SELECT j.id, j.kind, j.org_id
FROM jobs j
WHERE j.kind = ANY($1::text[]) AND `
	claimTail = `
  AND NOT EXISTS (SELECT 1 FROM saturated s WHERE s.kind = j.kind AND s.org_id = j.org_id)
  AND NOT EXISTS (SELECT 1 FROM unnest($5::text[], $6::uuid[]) AS x(kind, org_id)
                  WHERE x.kind = j.kind AND x.org_id = j.org_id)
ORDER BY j.priority DESC, j.run_at, j.id
LIMIT 1
FOR UPDATE OF j SKIP LOCKED`
	claimExpiredSQL = claimHead + `j.status = 'running' AND j.locked_until <= $2 AND j.attempts < j.max_attempts` + claimTail
	claimPendingSQL = claimHead + `j.status = 'pending' AND j.run_at <= $2` + claimTail
)

// claimed est un job pris : son exécution et le jeton de son bail.
type claimed struct {
	Execution
	token uuid.UUID
}

type orgKind struct {
	kind string
	org  uuid.UUID
}

// claim prend un job pour worker, ou renvoie nil s'il n'y en a pas.
func (r *Runner) claim(ctx context.Context, worker string) (*claimed, error) {
	var exclKinds []string
	var exclOrgs []uuid.UUID
	// Chaque essai qui échoue exclut un couple saturé : le nombre d'essais est borné
	// par celui des couples plafonnés réellement en concurrence.
	for range 8 {
		var got *claimed
		var sat orgKind
		err := r.stateTx(ctx, func(tx *db.Tx) error {
			now := r.clock.Now()
			var id uuid.UUID
			var kind string
			var org uuid.NullUUID
			err := sql.ErrNoRows
			for _, query := range []string{claimExpiredSQL, claimPendingSQL} {
				err = tx.QueryRowContext(ctx, query, r.kindNames, now, r.capKinds, r.caps, exclKinds, exclOrgs).
					Scan(&id, &kind, &org)
				if !errors.Is(err, sql.ErrNoRows) {
					break
				}
			}
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("jobs: prise : %w", err)
			}
			if limit := r.kinds[kind].orgLimit; limit > 0 && org.Valid {
				full, err := orgSaturated(ctx, tx, kind, org.UUID, limit, now)
				if err != nil {
					return err
				}
				if full {
					sat = orgKind{kind, org.UUID}
					return errSaturated
				}
			}
			got, err = lease(ctx, tx, id, worker, now.Add(r.o.Lease), now)
			return err
		})
		if errors.Is(err, errSaturated) {
			exclKinds, exclOrgs = append(exclKinds, sat.kind), append(exclOrgs, sat.org)
			continue
		}
		return got, err
	}
	return nil, nil
}

// orgSaturated recompte, sous un verrou consultatif de transaction propre au couple
// (type, organisation), les jobs en cours : deux workers ne peuvent pas franchir
// ensemble le plafond. Le verrou tombe à la fin de la transaction de prise, dont le
// résultat est alors visible du suivant (READ COMMITTED).
func orgSaturated(ctx context.Context, tx *db.Tx, kind string, org uuid.UUID, limit int, now time.Time) (bool, error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`,
		orgLimitLockClass, kind+"/"+org.String()); err != nil {
		return false, fmt.Errorf("jobs: verrou du plafond : %w", err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM jobs
		WHERE kind = $1 AND org_id = $2 AND status = 'running' AND locked_until > $3`,
		kind, org, now).Scan(&n); err != nil {
		return false, fmt.Errorf("jobs: comptage des jobs en cours : %w", err)
	}
	return n >= limit, nil
}

func lease(ctx context.Context, tx *db.Tx, id uuid.UUID, worker string, until, now time.Time) (*claimed, error) {
	c := &claimed{token: uuid.New()}
	var org uuid.NullUUID
	var key sql.NullString
	err := tx.QueryRowContext(ctx, `
		UPDATE jobs SET status = 'running', attempts = attempts + 1, locked_until = $2,
			lease_token = $3, worker = $4, updated_at = $5
		WHERE id = $1
		RETURNING id, kind, org_id, payload, priority, unique_key, attempts, max_attempts`,
		id, until, c.token, worker, now,
	).Scan(&c.ID, &c.Kind, &org, &c.Payload, &c.Priority, &key, &c.Attempt, &c.MaxAttempts)
	if err != nil {
		return nil, fmt.Errorf("jobs: pose du bail : %w", err)
	}
	if org.Valid {
		if c.OrgID, err = tenant.FromUUID(org.UUID); err != nil {
			return nil, err
		}
	}
	c.UniqueKey = key.String
	return c, nil
}

// renew prolonge le bail ; false : le bail n'est plus à nous (expiré et repris, ou
// libéré par l'arrêt).
func (r *Runner) renew(ctx context.Context, c *claimed) (bool, error) {
	now := r.clock.Now()
	n, err := r.exec(ctx, `
		UPDATE jobs SET locked_until = $3, updated_at = $4
		WHERE id = $1 AND lease_token = $2 AND status = 'running'`,
		c.ID, c.token, now.Add(r.o.Lease), now)
	if err != nil {
		return true, fmt.Errorf("jobs: renouvellement du bail : %w", err)
	}
	return n == 1, nil
}

// stateTx ouvre une transaction qui change l'état d'un job (prise, bail, fin), validée
// sans attendre l'écriture du journal sur disque (synchronous_commit à off pour elle
// seule) : si PostgreSQL tombe dans la fraction de seconde qui suit, la transaction est
// perdue en entier, et le job revient à l'état précédent (en attente, ou en cours au
// bail bientôt expiré) pour être rejoué, ce que la sémantique « au moins une fois »
// admet déjà. Une mise en file, elle, reste dans la transaction de l'appelant.
func (r *Runner) stateTx(ctx context.Context, fn func(*db.Tx) error) error {
	return r.pool.InTx(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx, `SET LOCAL synchronous_commit = off`); err != nil {
			return err
		}
		return fn(tx)
	})
}

// exec exécute une instruction sur la table globale jobs, dans sa propre transaction
// d'état (stateTx).
func (r *Runner) exec(ctx context.Context, query string, args ...any) (int64, error) {
	var n int64
	err := r.stateTx(ctx, func(tx *db.Tx) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// finish applique une fin de job si le bail est toujours le nôtre. false : bail perdu,
// la fin est ignorée (un autre worker a repris le job, ou l'arrêt l'a libéré).
func (r *Runner) finish(ctx context.Context, query string, args ...any) (bool, error) {
	n, err := r.exec(ctx, query, args...)
	return n == 1, err
}

func (r *Runner) complete(ctx context.Context, c *claimed) (bool, error) {
	now := r.clock.Now()
	ok, err := r.finish(ctx, `
		UPDATE jobs SET status = 'done', finished_at = $3, updated_at = $3,
			locked_until = NULL, lease_token = NULL, worker = NULL, last_error = NULL
		WHERE id = $1 AND lease_token = $2`, c.ID, c.token, now)
	if err != nil {
		return false, fmt.Errorf("jobs: fin du job : %w", err)
	}
	return ok, nil
}

func (r *Runner) bury(ctx context.Context, c *claimed, cause error) (bool, error) {
	now := r.clock.Now()
	ok, err := r.finish(ctx, `
		UPDATE jobs SET status = 'dead', finished_at = $3, updated_at = $3, last_error = $4,
			locked_until = NULL, lease_token = NULL, worker = NULL
		WHERE id = $1 AND lease_token = $2`, c.ID, c.token, now, errorText(cause))
	if err != nil {
		return false, fmt.Errorf("jobs: passage en dead : %w", err)
	}
	return ok, nil
}

// requeue remet le job en attente à runAt (zéro : échéance inchangée). undo annule la tentative (libération à
// l'arrêt : le job n'y est pour rien) ; cause, si non nil, devient la dernière erreur.
func (r *Runner) requeue(ctx context.Context, c *claimed, runAt time.Time, cause error, undo bool) (bool, error) {
	now := r.clock.Now()
	undoAttempt := 0
	if undo {
		undoAttempt = 1
	}
	var at, msg any
	if !runAt.IsZero() {
		at = runAt
	}
	if cause != nil {
		msg = errorText(cause)
	}
	ok, err := r.finish(ctx, `
		UPDATE jobs SET status = 'pending', run_at = COALESCE($3, run_at), updated_at = $4,
			attempts = attempts - $5, last_error = COALESCE($6, last_error),
			locked_until = NULL, lease_token = NULL, worker = NULL
		WHERE id = $1 AND lease_token = $2`, c.ID, c.token, at, now, undoAttempt, msg)
	if isUniqueViolation(err) {
		// Un job de même clé est déjà en attente : il fera le travail, celui-ci s'efface.
		ok, err = r.finish(ctx, `DELETE FROM jobs WHERE id = $1 AND lease_token = $2`, c.ID, c.token)
	}
	if err != nil {
		return false, fmt.Errorf("jobs: remise en attente : %w", err)
	}
	return ok, nil
}

// release remet en attente les jobs interrompus par l'arrêt, en une instruction, sans
// compter la tentative ni changer l'échéance. Si l'un d'eux a un jumeau en attente, chacun
// est traité à part.
func (r *Runner) release(ctx context.Context, jobs []*claimed) error {
	if len(jobs) == 0 {
		return nil
	}
	tokens := make([]uuid.UUID, len(jobs))
	for i, c := range jobs {
		tokens[i] = c.token
	}
	_, err := r.exec(ctx, `
		UPDATE jobs SET status = 'pending', attempts = attempts - 1, updated_at = $2,
			locked_until = NULL, lease_token = NULL, worker = NULL
		WHERE lease_token = ANY($1::uuid[])`, tokens, r.clock.Now())
	if !isUniqueViolation(err) {
		if err != nil {
			return fmt.Errorf("jobs: libération des baux : %w", err)
		}
		return nil
	}
	var errs []error
	for _, c := range jobs {
		if _, err := r.requeue(ctx, c, time.Time{}, nil, true); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reapExhausted passe en dead les jobs dont le bail a expiré pendant leur dernière
// tentative : le worker a disparu, et aucun autre ne les reprendra.
func (r *Runner) reapExhausted(ctx context.Context) (int64, error) {
	now := r.clock.Now()
	n, err := r.exec(ctx, `
		UPDATE jobs SET status = 'dead', finished_at = $1, updated_at = $1,
			last_error = 'bail expiré pendant la dernière tentative (worker disparu)',
			locked_until = NULL, lease_token = NULL, worker = NULL
		WHERE status = 'running' AND locked_until <= $1 AND attempts >= max_attempts`, now)
	if err != nil {
		return 0, fmt.Errorf("jobs: jobs épuisés : %w", err)
	}
	return n, nil
}

// purge supprime les jobs terminés depuis plus que la rétention, par lots, sans bloquer
// une autre instance qui purge en même temps.
func (r *Runner) purge(ctx context.Context) (int64, error) {
	before := r.clock.Now().Add(-r.o.Retention)
	var total int64
	for {
		n, err := r.exec(ctx, `
			DELETE FROM jobs WHERE id IN (
				SELECT id FROM jobs WHERE status = 'done' AND finished_at < $1
				LIMIT $2 FOR UPDATE SKIP LOCKED)`, before, purgeBatch)
		if err != nil {
			return total, fmt.Errorf("jobs: purge : %w", err)
		}
		total += n
		if n < purgeBatch {
			return total, nil
		}
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// errorText tronque un message d'erreur sur une limite de caractère.
func errorText(err error) string {
	s := strings.ToValidUTF8(err.Error(), "\uFFFD")
	if len(s) <= maxErrorLen {
		return s
	}
	s = s[:maxErrorLen]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}
