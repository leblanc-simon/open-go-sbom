package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/tenant"
)

// Administration des jobs morts, pour l'écran d'administration de l'instance (T11).
// Les fonctions travaillent dans la transaction de l'appelant, qui peut y écrire son
// entrée d'audit.

// MaxListLimit borne une page de ListDead.
const MaxListLimit = 200

// DeadJob est un job abandonné après épuisement de ses tentatives ou erreur permanente.
type DeadJob struct {
	ID          uuid.UUID
	Kind        string
	OrgID       tenant.OrgID // zéro pour un job d'instance
	UniqueKey   string
	Attempts    int
	MaxAttempts int
	LastError   string
	CreatedAt   time.Time
	FinishedAt  time.Time
}

type deadKey struct {
	FinishedAt time.Time `json:"f"`
	ID         uuid.UUID `json:"i"`
}

const deadColumns = `id, kind, org_id, unique_key, attempts, max_attempts, COALESCE(last_error, ''), created_at, finished_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanDead(row rowScanner) (DeadJob, error) {
	var d DeadJob
	var org uuid.NullUUID
	var key sql.NullString
	if err := row.Scan(&d.ID, &d.Kind, &org, &key, &d.Attempts, &d.MaxAttempts, &d.LastError, &d.CreatedAt, &d.FinishedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeadJob{}, ErrNotFound
		}
		return DeadJob{}, fmt.Errorf("jobs: lecture d'un job mort : %w", err)
	}
	if org.Valid {
		var err error
		if d.OrgID, err = tenant.FromUUID(org.UUID); err != nil {
			return DeadJob{}, err
		}
	}
	d.UniqueKey = key.String
	d.CreatedAt, d.FinishedAt = d.CreatedAt.UTC(), d.FinishedAt.UTC()
	return d, nil
}

// GetDead lit le job mort id et le verrouille jusqu'à la fin de la transaction de
// l'appelant (relance ou suppression qui suit). ErrNotFound si id ne désigne pas un job
// mort.
func GetDead(ctx context.Context, q db.Querier, id uuid.UUID) (DeadJob, error) {
	return scanDead(q.QueryRowContext(ctx, `SELECT `+deadColumns+` FROM jobs WHERE id = $1 AND status = 'dead' FOR UPDATE`, id))
}

// ListDead liste les jobs morts, du plus récent au plus ancien. cursor vient de la page
// précédente (vide pour la première) ; limit est dans [1, MaxListLimit].
func ListDead(ctx context.Context, q db.Querier, cursor string, limit int) (pagination.Page[DeadJob], error) {
	var none pagination.Page[DeadJob]
	if limit < 1 || limit > MaxListLimit {
		return none, &pagination.LimitError{Max: MaxListLimit}
	}
	var after *deadKey
	if cursor != "" {
		after = &deadKey{}
		if err := pagination.Decode(cursor, after); err != nil {
			return none, err
		}
	}
	query := `SELECT ` + deadColumns + ` FROM jobs WHERE status = 'dead'`
	args := []any{limit + 1}
	if after != nil {
		query += ` AND (finished_at, id) < ($2, $3)`
		args = append(args, after.FinishedAt, after.ID)
	}
	query += ` ORDER BY finished_at DESC, id DESC LIMIT $1`
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return none, fmt.Errorf("jobs: liste des jobs morts : %w", err)
	}
	defer rows.Close()
	var out []DeadJob
	for rows.Next() {
		d, err := scanDead(rows)
		if err != nil {
			return none, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return none, fmt.Errorf("jobs: liste des jobs morts : %w", err)
	}
	return pagination.Build(out, limit, func(d DeadJob) any { return deadKey{d.FinishedAt, d.ID} })
}

// Retry remet un job mort en attente, pour maintenant et avec toutes ses tentatives. Si
// un job de même type et de même clé d'unicité est déjà en attente, il fera le travail :
// le job mort est alors simplement supprimé. ErrNotFound si id ne désigne pas un job
// mort.
func Retry(ctx context.Context, q db.Querier, id uuid.UUID) error {
	now := time.Now()
	// Le point de sauvegarde garde utilisable la transaction de l'appelant quand la mise à
	// jour heurte un job en attente de même clé (index unique).
	if _, err := q.ExecContext(ctx, `SAVEPOINT jobs_retry`); err != nil {
		return fmt.Errorf("jobs: relance : %w", err)
	}
	res, err := q.ExecContext(ctx, `
		UPDATE jobs SET status = 'pending', attempts = 0, run_at = $2, updated_at = $2, finished_at = NULL
		WHERE id = $1 AND status = 'dead'`, id, now)
	if isUniqueViolation(err) {
		if _, err := q.ExecContext(ctx, `ROLLBACK TO SAVEPOINT jobs_retry`); err != nil {
			return fmt.Errorf("jobs: relance : %w", err)
		}
		return Discard(ctx, q, id)
	}
	if err != nil {
		return fmt.Errorf("jobs: relance : %w", err)
	}
	if _, err := q.ExecContext(ctx, `RELEASE SAVEPOINT jobs_retry`); err != nil {
		return fmt.Errorf("jobs: relance : %w", err)
	}
	return oneRow(res)
}

// Discard supprime un job mort. ErrNotFound si id ne désigne pas un job mort.
func Discard(ctx context.Context, q db.Querier, id uuid.UUID) error {
	res, err := q.ExecContext(ctx, `DELETE FROM jobs WHERE id = $1 AND status = 'dead'`, id)
	if err != nil {
		return fmt.Errorf("jobs: suppression : %w", err)
	}
	return oneRow(res)
}

// Counts compte les jobs qui ne sont pas terminés.
type Counts struct {
	Pending, Running, Dead int
}

// CountJobs compte les jobs en attente, en cours et morts (écran d'administration) ;
// chaque compte passe par l'index partiel de son statut.
func CountJobs(ctx context.Context, q db.Querier) (Counts, error) {
	var c Counts
	err := q.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM jobs WHERE status = 'pending'),
		(SELECT count(*) FROM jobs WHERE status = 'running'),
		(SELECT count(*) FROM jobs WHERE status = 'dead')`).Scan(&c.Pending, &c.Running, &c.Dead)
	if err != nil {
		return Counts{}, fmt.Errorf("jobs: comptage : %w", err)
	}
	return c, nil
}

// Active indique si un job de type kind et de clé d'unicité key est en attente ou en
// cours.
func Active(ctx context.Context, q db.Querier, kind, key string) (bool, error) {
	var ok bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM jobs
		WHERE kind = $1 AND unique_key = $2 AND status IN ('pending', 'running'))`, kind, key).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("jobs: recherche d'un job actif : %w", err)
	}
	return ok, nil
}

func oneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
