package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/tenant"
)

// RetentionPolicy règle la rétention des instantanés (ADR 0039). Tout instantané de moins
// de Days jours est gardé, ainsi que les Count plus récents de chaque référence ; au-delà,
// Monthly garde le dernier instantané de chaque mois (UTC). Ne sont jamais supprimés le
// dernier instantané d'une référence (son instantané courant), l'instantané en vigueur au
// début de la fenêtre (le dernier plus ancien que la coupure), un instantané reçu depuis
// moins de Days jours, ni l'instantané de la dernière analyse d'une référence.
type RetentionPolicy struct {
	// Enabled : sans rétention, aucun instantané ni aucune réception n'est supprimé ; les
	// ensembles et SBOM orphelins le sont toujours.
	Enabled bool
	Days    int
	Count   int
	Monthly bool
	// ContainerPurgeAfter : un conteneur archivé pour absence depuis plus longtemps est
	// supprimé avec son historique (0 : jamais), qu'Enabled soit posé ou non (T18,
	// ADR 0048). Au moins Days jours : la fenêtre détaillée de son historique est passée.
	ContainerPurgeAfter time.Duration
}

// Bornes de la politique de rétention.
const (
	RetentionMaxDays  = 36500
	RetentionMaxCount = 100000
)

// DefaultRetention est la politique décidée le 1er novembre 2026 : tout garder 90 jours,
// puis un instantané par mois, sans limite de durée.
func DefaultRetention() RetentionPolicy {
	return RetentionPolicy{Enabled: true, Days: 90, Monthly: true}
}

// Validate vérifie les bornes de la politique.
func (p RetentionPolicy) Validate() error {
	if p.Days < 1 || p.Days > RetentionMaxDays {
		return fmt.Errorf("inventory: durée de rétention de %d jours hors de [1, %d]", p.Days, RetentionMaxDays)
	}
	if p.Count < 0 || p.Count > RetentionMaxCount {
		return fmt.Errorf("inventory: nombre d'instantanés gardés %d hors de [0, %d]", p.Count, RetentionMaxCount)
	}
	if p.ContainerPurgeAfter != 0 && p.ContainerPurgeAfter < time.Duration(p.Days)*24*time.Hour {
		return fmt.Errorf("inventory: purge des conteneurs après %s, sous la fenêtre de rétention de %d jours", p.ContainerPurgeAfter, p.Days)
	}
	return nil
}

// Cutoff est la date de coupure à l'instant now : les instantanés scannés avant elle
// sortent de la fenêtre.
func (p RetentionPolicy) Cutoff(now time.Time) time.Time {
	return now.Add(-time.Duration(p.Days) * 24 * time.Hour)
}

// Types des jobs de la rétention.
const (
	// RetentionAllKind met en file un RetentionOrgKind par organisation.
	RetentionAllKind = "retention.snapshots_all"
	// RetentionOrgKind applique la rétention à une organisation.
	RetentionOrgKind = "retention.snapshots_org"
)

// RetentionSchedule est l'échéance quotidienne de la rétention, à 02:30 UTC.
func RetentionSchedule() jobs.Schedule {
	return jobs.Schedule{Name: RetentionAllKind, Every: 24 * time.Hour, Offset: 2*time.Hour + 30*time.Minute,
		Job: jobs.Job{Kind: RetentionAllKind, Priority: jobs.PriorityLow}}
}

// retentionBatch borne les ensembles et SBOM orphelins supprimés par transaction.
const retentionBatch = 500

// RetentionReport compte ce qu'un passage a supprimé.
type RetentionReport struct {
	Snapshots  int64
	Ingestions int64
	Sets       int64
	Blobs      int64
	Diffs      int64
	// Containers : projets de conteneurs supprimés (ContainerPurgeAfter).
	Containers int64
	// Recompute : références dont les différences sont mises en file.
	Recompute int
}

// RetentionAllHandler est le handler de RetentionAllKind : un RetentionOrgKind par
// organisation, archivées comprises (leur historique occupe aussi de la place).
// Idempotent : la clé d'unicité fond les mises en file répétées.
func (h *History) RetentionAllHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		_, err := h.EnqueueRetention(ctx)
		return err
	})
}

// EnqueueRetention met en file la rétention de chaque organisation et en renvoie le
// nombre (liste par crossorg, § 16).
func (h *History) EnqueueRetention(ctx context.Context) (int, error) {
	n := 0
	after := ""
	for {
		var page []crossorg.OrgSummary
		err := h.pool.InTx(ctx, func(tx *db.Tx) error {
			var err error
			if page, err = crossorg.ListOrganizations(ctx, tx, after, crossorg.MaxPage); err != nil {
				return err
			}
			for _, o := range page {
				if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: RetentionOrgKind, OrgID: o.Org, Priority: jobs.PriorityLow,
					UniqueKey: "org:" + o.Org.String()}); err != nil {
					return err
				}
				n++
			}
			return nil
		})
		if err != nil {
			return n, fmt.Errorf("inventory: rétention du parc : %w", err)
		}
		if len(page) < crossorg.MaxPage {
			return n, nil
		}
		after = page[len(page)-1].Slug
	}
}

// RetentionOrgHandler est le handler de RetentionOrgKind.
func (h *History) RetentionOrgHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(fmt.Errorf("inventory: %s sans organisation", RetentionOrgKind))
		}
		_, err := h.Retain(ctx, e.OrgID)
		return err
	})
}

// Retain applique la rétention à une organisation : instantanés hors politique et leurs
// réceptions, réceptions terminées hors de la fenêtre, puis ensembles et SBOM devenus
// orphelins, différences qui ne relient plus deux instantanés consécutifs ; il met en
// file le calcul des différences manquantes. Chaque étape est idempotente : un passage
// interrompu est repris par le suivant.
func (h *History) Retain(ctx context.Context, org tenant.OrgID) (RetentionReport, error) {
	now := h.clock.Now().UTC().Round(time.Microsecond)
	cutoff := h.policy.Cutoff(now)
	var rep RetentionReport
	if h.policy.Enabled {
		refs, err := h.refsWithOldSnapshots(ctx, org, cutoff)
		if err != nil {
			return rep, err
		}
		for _, ref := range refs {
			snaps, ins, err := h.retainRef(ctx, org, ref, cutoff)
			if err != nil {
				return rep, err
			}
			rep.Snapshots += snaps
			rep.Ingestions += ins
		}
		err = h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
			res, err := tx.ExecContext(ctx, `DELETE FROM ingestions WHERE status IN ('done', 'failed') AND received_at < $1`, cutoff)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			rep.Ingestions += n
			return err
		})
		if err != nil {
			return rep, wrap("réceptions hors de la fenêtre", err)
		}
	}
	if h.policy.ContainerPurgeAfter > 0 {
		n, err := h.purgeContainers(ctx, org, now.Add(-h.policy.ContainerPurgeAfter))
		rep.Containers = n
		if err != nil {
			return rep, wrap("purge des conteneurs archivés", err)
		}
	}
	var err error
	if rep.Sets, err = h.deleteOrphans(ctx, org, orphanSets); err != nil {
		return rep, wrap("ensembles orphelins", err)
	}
	if rep.Blobs, err = h.deleteOrphans(ctx, org, orphanBlobs); err != nil {
		return rep, wrap("SBOM orphelins", err)
	}
	err = h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if rep.Diffs, err = deleteStaleDiffs(ctx, tx); err != nil {
			return err
		}
		refs, err := refsMissingDiffs(ctx, tx)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if err := enqueueDiff(ctx, tx, ref); err != nil {
				return err
			}
		}
		rep.Recompute = len(refs)
		if !h.policy.Enabled {
			return nil
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO snapshot_retention (org_id, horizon, last_run_at, snapshots_deleted, ingestions_deleted, sets_deleted, blobs_deleted)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (org_id) DO UPDATE SET horizon = GREATEST(snapshot_retention.horizon, EXCLUDED.horizon),
			       last_run_at = EXCLUDED.last_run_at, snapshots_deleted = EXCLUDED.snapshots_deleted,
			       ingestions_deleted = EXCLUDED.ingestions_deleted, sets_deleted = EXCLUDED.sets_deleted,
			       blobs_deleted = EXCLUDED.blobs_deleted`,
			tx.OrgID(), cutoff, now, rep.Snapshots, rep.Ingestions, rep.Sets, rep.Blobs)
		return err
	})
	if err != nil {
		return rep, wrap("différences et bilan de la rétention", err)
	}
	h.logger.Info("rétention des instantanés", "org", org.String(), "snapshots", rep.Snapshots, "ingestions", rep.Ingestions,
		"sets", rep.Sets, "blobs", rep.Blobs, "diffs", rep.Diffs, "containers", rep.Containers, "recompute", rep.Recompute)
	return rep, nil
}

// refsWithOldSnapshots renvoie les références qui ont plus d'un instantané et au moins un
// hors de la fenêtre.
func (h *History) refsWithOldSnapshots(ctx context.Context, org tenant.OrgID, cutoff time.Time) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT ref_id FROM snapshots GROUP BY ref_id
			HAVING count(*) > 1 AND bool_or(scanned_at < $1 AND created_at < $1) ORDER BY ref_id`, cutoff)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("références à réduire", err)
}

// retainRef supprime, sous le verrou de la référence (celui de l'ingestion), ses
// instantanés hors politique et leurs réceptions. La sélection se fait sous le verrou :
// une ingestion concurrente ne peut pas changer l'ordre des instantanés entre la décision
// et la suppression.
func (h *History) retainRef(ctx context.Context, org tenant.OrgID, refID uuid.UUID, cutoff time.Time) (int64, int64, error) {
	var n, ins int64
	err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM tracked_refs WHERE id = $1 FOR UPDATE`, refID); err != nil {
			return err
		}
		ids, err := expiredSnapshots(ctx, tx, refID, cutoff, h.policy)
		if err != nil || len(ids) == 0 {
			return err
		}
		strs := make([]string, len(ids))
		for i, id := range ids {
			strs[i] = id.String()
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM ingestions WHERE snapshot_id = ANY($1::uuid[])`, strs)
		if err != nil {
			return err
		}
		if ins, err = res.RowsAffected(); err != nil {
			return err
		}
		res, err = tx.ExecContext(ctx, `DELETE FROM snapshots WHERE id = ANY($1::uuid[])`, strs)
		if err != nil {
			return err
		}
		if n, err = res.RowsAffected(); err != nil {
			return err
		}
		// De nouveaux couples d'instantanés consécutifs apparaissent.
		return enqueueDiff(ctx, tx, refID)
	})
	return n, ins, wrap("rétention d'une référence", err)
}

// expiredSnapshots applique la politique aux instantanés d'une référence et renvoie ceux
// à supprimer. Le rang du mois et celui de l'instantané en vigueur à la coupure se
// calculent parmi les seuls instantanés hors de la fenêtre : le dernier d'entre eux, en
// vigueur au début de la fenêtre, est toujours gardé, si bien qu'à toute date de la
// fenêtre l'instantané en vigueur existe encore.
func expiredSnapshots(ctx context.Context, tx *db.OrgTx, refID uuid.UUID, cutoff time.Time, p RetentionPolicy) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH ranked AS (
		    SELECT id, scanned_at, created_at, row_number() OVER (ORDER BY scanned_at DESC, id DESC) AS rank
		      FROM snapshots WHERE ref_id = $1
		), old AS (
		    SELECT id, rank,
		           row_number() OVER (ORDER BY scanned_at DESC, id DESC) AS old_rank,
		           row_number() OVER (PARTITION BY date_trunc('month', scanned_at AT TIME ZONE 'UTC')
		                              ORDER BY scanned_at DESC, id DESC) AS month_rank
		      FROM ranked WHERE scanned_at < $2 AND created_at < $2
		)
		SELECT o.id FROM old o
		 WHERE o.rank > greatest($3::int, 1) AND o.old_rank > 1 AND (NOT $4 OR o.month_rank > 1)
		   AND NOT EXISTS (SELECT 1 FROM ref_current rc WHERE rc.snapshot_id = o.id)
		   AND NOT EXISTS (SELECT 1 FROM ref_analyses ra WHERE ra.snapshot_id = o.id)
		 ORDER BY o.id`, refID, cutoff, p.Count, p.Monthly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// orphanQuery décrit une table dont on supprime les lignes que plus rien ne référence.
type orphanQuery struct {
	table string
	// unreferenced est la condition « orphelin » sur l'alias t.
	unreferenced string
}

var (
	orphanSets = orphanQuery{table: "component_sets", unreferenced: `
		NOT EXISTS (SELECT 1 FROM snapshots s WHERE s.org_id = t.org_id AND s.set_id = t.id)
		AND NOT EXISTS (SELECT 1 FROM ref_current rc WHERE rc.org_id = t.org_id AND rc.set_id = t.id)
		AND NOT EXISTS (SELECT 1 FROM ref_analyses ra WHERE ra.org_id = t.org_id AND ra.set_id = t.id)`}
	orphanBlobs = orphanQuery{table: "sbom_blobs", unreferenced: `
		NOT EXISTS (SELECT 1 FROM snapshots s WHERE s.org_id = t.org_id AND s.blob_id = t.id)
		AND NOT EXISTS (SELECT 1 FROM ingestions i WHERE i.org_id = t.org_id AND i.blob_id = t.id)`}
)

// deleteOrphans supprime par lots les lignes orphelines d'une table. Chaque lot verrouille
// d'abord les candidats en sautant ceux qu'une ingestion tient (elle les verrouille avant
// de les référencer, FOR KEY SHARE), puis supprime ceux qui sont toujours orphelins vus
// de l'instruction suivante : une référence validée entre-temps est vue, et la ligne
// reste.
func (h *History) deleteOrphans(ctx context.Context, org tenant.OrgID, q orphanQuery) (int64, error) {
	var total int64
	after := uuid.Nil
	for {
		var selected int
		err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
			rows, err := tx.QueryContext(ctx, `SELECT t.id FROM `+q.table+` t WHERE t.id > $1 AND `+q.unreferenced+`
				ORDER BY t.id LIMIT $2 FOR UPDATE OF t SKIP LOCKED`, after, retentionBatch)
			if err != nil {
				return err
			}
			var ids []string
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, id.String())
				after = id
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
			selected = len(ids)
			if selected == 0 {
				return nil
			}
			res, err := tx.ExecContext(ctx, `DELETE FROM `+q.table+` t WHERE t.id = ANY($1::uuid[]) AND `+q.unreferenced, ids)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			total += n
			return err
		})
		if err != nil {
			return total, err
		}
		if selected < retentionBatch {
			return total, nil
		}
	}
}

// adjacentPairs liste les couples d'ensembles d'instantanés consécutifs de chaque
// référence (date de scan, puis identifiant).
const adjacentPairs = `
	SELECT ref_id, set_id, lag(set_id) OVER (PARTITION BY ref_id ORDER BY scanned_at, id) AS prev FROM snapshots`

// deleteStaleDiffs supprime les différences qui ne relient plus deux instantanés
// consécutifs d'aucune référence (instantané intermédiaire supprimé, commit remplacé).
func deleteStaleDiffs(ctx context.Context, tx *db.OrgTx) (int64, error) {
	res, err := tx.ExecContext(ctx, `
		DELETE FROM set_diffs d WHERE NOT EXISTS (
		    SELECT 1 FROM (`+adjacentPairs+`) x WHERE x.prev = d.from_set_id AND x.set_id = d.to_set_id)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// refsMissingDiffs renvoie les références dont un couple d'instantanés consécutifs n'a
// pas sa différence (historique réduit, instantané arrivé dans le désordre, données
// antérieures à T17).
func refsMissingDiffs(ctx context.Context, tx *db.OrgTx) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT x.ref_id FROM (`+adjacentPairs+`) x
		 WHERE x.prev IS NOT NULL AND x.prev <> x.set_id
		   AND NOT EXISTS (SELECT 1 FROM set_diffs d WHERE d.from_set_id = x.prev AND d.to_set_id = x.set_id)
		 ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RetentionState est le dernier passage de la rétention d'une organisation.
type RetentionState struct {
	// Horizon est la plus récente coupure appliquée : avant elle, l'historique d'une
	// référence est réduit à un instantané par mois (ou moins sans Monthly), et une
	// recherche à une date antérieure (T21) ne voit qu'une partie des états passés.
	Horizon   time.Time
	LastRunAt time.Time
	Report    RetentionReport
}

// ReadRetention lit le dernier passage de la rétention ; faux si elle n'est jamais
// passée dans l'organisation (historique complet).
func ReadRetention(ctx context.Context, tx *db.OrgTx) (RetentionState, bool, error) {
	var st RetentionState
	err := tx.QueryRowContext(ctx, `
		SELECT horizon, last_run_at, snapshots_deleted, ingestions_deleted, sets_deleted, blobs_deleted FROM snapshot_retention`).
		Scan(&st.Horizon, &st.LastRunAt, &st.Report.Snapshots, &st.Report.Ingestions, &st.Report.Sets, &st.Report.Blobs)
	if errors.Is(err, sql.ErrNoRows) {
		return RetentionState{}, false, nil
	}
	if err != nil {
		return RetentionState{}, false, wrap("rétention", err)
	}
	st.Horizon, st.LastRunAt = st.Horizon.UTC(), st.LastRunAt.UTC()
	return st, true, nil
}

// Retention : voir ReadRetention.
func (h *History) Retention(ctx context.Context, org tenant.OrgID) (st RetentionState, ok bool, err error) {
	err = h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		st, ok, err = ReadRetention(ctx, tx)
		return err
	}, db.ReadOnly())
	return st, ok, err
}

// containerPurgeBatch borne les conteneurs supprimés par transaction.
const containerPurgeBatch = 50

// purgeContainers supprime les projets des conteneurs archivés pour absence avant before,
// avec tout leur historique (instantanés, réceptions, constats, analyses, violations), par
// lots ; ensembles, SBOM et différences devenus orphelins partent ensuite avec les étapes
// communes de la rétention. Ne sont jamais purgés : un conteneur archivé par un
// utilisateur (son archivage dit à l'agent de l'ignorer, le supprimer le ferait revenir),
// ni un conteneur qui porte une décision de triage (le journal des décisions est en ajout
// seul). Chaque suppression est journalisée (project.purged, acteur système). Idempotent ;
// un conteneur qui réapparaît pendant le passage est protégé par le verrou de sa ligne,
// pris avant la suppression et sous lequel la condition est vérifiée de nouveau.
func (h *History) purgeContainers(ctx context.Context, org tenant.OrgID, before time.Time) (int64, error) {
	var total int64
	for {
		var n int
		err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
			rows, err := tx.QueryContext(ctx, `
				SELECT p.id, p.slug, p.archived_at, coalesce(pp.slug, '') FROM projects p
				  LEFT JOIN projects pp ON pp.org_id = p.org_id AND pp.id = p.parent_id
				 WHERE p.kind = 'container' AND p.archived_absent AND p.archived_at < $1
				   AND NOT EXISTS (SELECT 1 FROM triage_decisions d WHERE d.org_id = p.org_id AND d.project_id = p.id)
				 ORDER BY p.archived_at, p.id LIMIT $2 FOR UPDATE OF p SKIP LOCKED`, before, containerPurgeBatch)
			if err != nil {
				return err
			}
			type victim struct {
				id         uuid.UUID
				slug, host string
				archived   time.Time
			}
			var victims []victim
			for rows.Next() {
				var v victim
				if err := rows.Scan(&v.id, &v.slug, &v.archived, &v.host); err != nil {
					rows.Close()
					return err
				}
				victims = append(victims, v)
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
			n = len(victims)
			if n == 0 {
				return nil
			}
			ids := make([]string, n)
			for i, v := range victims {
				ids[i] = v.id.String()
			}
			// Références verrouillées comme par l'ingestion : aucune réception ne s'écrit
			// pendant la suppression.
			if _, err := tx.ExecContext(ctx, `SELECT 1 FROM tracked_refs WHERE project_id = ANY($1::uuid[]) FOR UPDATE`, ids); err != nil {
				return err
			}
			for _, q := range []string{
				`DELETE FROM ref_current WHERE project_id = ANY($1::uuid[])`,
				`DELETE FROM ref_analyses WHERE project_id = ANY($1::uuid[])`,
				`DELETE FROM findings WHERE project_id = ANY($1::uuid[])`,
				`DELETE FROM ingestions WHERE project_id = ANY($1::uuid[])`,
				`DELETE FROM snapshots WHERE project_id = ANY($1::uuid[])`,
				// Références, évaluations et violations restantes, statistiques : en cascade.
				`DELETE FROM projects WHERE id = ANY($1::uuid[])`,
			} {
				if _, err := tx.ExecContext(ctx, q, ids); err != nil {
					return err
				}
			}
			for _, v := range victims {
				if err := audit.RecordOrg(ctx, tx, audit.System, audit.Event{Action: audit.ProjectPurged, TargetType: "project",
					TargetID: v.id.String(), TargetLabel: v.slug,
					Details: map[string]string{"reason": "archived_absent", "host": v.host,
						"archived_at": v.archived.UTC().Format(time.RFC3339)}}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total += int64(n)
		if n < containerPurgeBatch {
			return total, nil
		}
	}
}
