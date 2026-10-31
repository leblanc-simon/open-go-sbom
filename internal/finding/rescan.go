package finding

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/jobs"
)

// RescanOrgKind réanalyse les références actives d'une organisation : analysis.rescan_all
// en met un en file par organisation active.
const RescanOrgKind = "analysis.rescan_org"

// rescanPage borne les références mises en file par transaction.
const rescanPage = 500

// RescanAllHandler est le handler de vuln.RescanAllKind : il met en file un
// analysis.rescan_org par organisation active (liste par crossorg, § 16). Idempotent :
// la clé d'unicité fond les mises en file répétées.
func (a *Analyzer) RescanAllHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		_, err := a.RescanAll(ctx)
		return err
	})
}

// RescanAll met en file la réanalyse de chaque organisation active et en renvoie le nombre.
func (a *Analyzer) RescanAll(ctx context.Context) (int, error) {
	n := 0
	after := ""
	for {
		var page []crossorg.OrgSummary
		err := a.o.Pool.InTx(ctx, func(tx *db.Tx) error {
			var err error
			if page, err = crossorg.ListOrganizations(ctx, tx, after, crossorg.MaxPage); err != nil {
				return err
			}
			for _, o := range page {
				if o.ArchivedAt != nil {
					continue
				}
				if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: RescanOrgKind, OrgID: o.Org, Priority: jobs.PriorityLow,
					UniqueKey: "org:" + o.Org.String()}); err != nil {
					return err
				}
				n++
			}
			return nil
		})
		if err != nil {
			return n, fmt.Errorf("finding: réanalyse du parc : %w", err)
		}
		if len(page) < crossorg.MaxPage {
			return n, nil
		}
		after = page[len(page)-1].Slug
	}
}

// RescanOrgHandler est le handler de RescanOrgKind.
func (a *Analyzer) RescanOrgHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(fmt.Errorf("finding: %s sans organisation", RescanOrgKind))
		}
		_, err := a.RescanOrg(ctx, e)
		return err
	})
}

// RescanOrg met en file, en priorité basse, l'analyse de chaque référence active de
// l'organisation qui a un inventaire : référence non retirée d'un projet non archivé. La
// clé d'unicité d'analysis.ref fond cette mise en file avec une analyse déjà en attente
// (dont elle garde la priorité, plus haute pour une ingestion fraîche) ; une référence
// déjà analysée avec la base cible ne refait rien (Analyze).
func (a *Analyzer) RescanOrg(ctx context.Context, e jobs.Execution) (int, error) {
	n := 0
	after := uuid.Nil
	for {
		var refs []uuid.UUID
		err := a.o.Pool.InOrg(ctx, e.OrgID, func(tx *db.OrgTx) error {
			rows, err := tx.QueryContext(ctx, `
				SELECT r.id FROM tracked_refs r
				  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id
				  JOIN ref_current rc ON rc.org_id = r.org_id AND rc.ref_id = r.id
				 WHERE r.removed_at IS NULL AND p.archived_at IS NULL AND r.id > $1
				 ORDER BY r.id LIMIT $2`, after, rescanPage)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				refs = append(refs, id)
			}
			if err := closeRows(rows); err != nil {
				return err
			}
			for _, id := range refs {
				if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: inventory.AnalysisKind,
					Payload: inventory.AnalysisPayload{RefID: id}, Priority: jobs.PriorityLow,
					UniqueKey: inventory.AnalysisUniqueKey(id)}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return n, fmt.Errorf("finding: réanalyse de l'organisation : %w", err)
		}
		n += len(refs)
		if len(refs) < rescanPage {
			return n, nil
		}
		after = refs[len(refs)-1]
	}
}
