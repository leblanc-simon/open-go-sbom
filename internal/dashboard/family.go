package dashboard

import (
	"context"
	"math"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// Perimeter est l'état d'un projet d'une famille (l'hôte ou l'un de ses conteneurs) :
// vulnérabilités ouvertes distinctes par sévérité, dont KEV, et risque maximal.
type Perimeter struct {
	Open    Counts
	MaxRisk float64
}

// Family réunit les constats ouverts d'un hôte et de ses conteneurs (T13). Chaque projet
// compte ses vulnérabilités distinctes : une vulnérabilité présente dans deux composants
// d'un même conteneur compte une fois, la même vulnérabilité sur l'hôte et sur deux
// conteneurs compte trois fois. Total additionne ainsi les couples distincts (projet,
// vulnérabilité) de l'hôte et de ses conteneurs actifs.
type Family struct {
	Host     Perimeter
	Children map[uuid.UUID]Perimeter
	Total    Perimeter
}

// Family lit les constats ouverts de l'hôte hostID et de ses conteneurs, hors constats
// triés « non affecté » ou « faux positif » comme le reste du tableau de bord (T14). La
// sévérité d'un couple est la plus haute de ses constats ; il est KEV si l'un d'eux l'est. Les
// conteneurs archivés ont leur état, mais n'entrent pas dans le total. L'appelant a
// vérifié que l'hôte est visible ; ses conteneurs sont dans son équipe.
func (s *Service) Family(ctx context.Context, org tenant.OrgID, hostID uuid.UUID) (Family, error) {
	out := Family{Host: newPerimeter(), Children: map[uuid.UUID]Perimeter{}, Total: newPerimeter()}
	err := s.read(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			WITH family AS (
				SELECT id, archived_at IS NULL AS active FROM projects
				 WHERE id = $1 OR (parent_id = $1 AND kind = 'container')),
			pairs AS (
				SELECT f.project_id, f.vuln_id, max(`+severityRank+`) AS rank, bool_or(f.kev) AS kev, max(f.risk) AS risk
				  FROM findings f JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
				 WHERE f.status = 'open' AND r.removed_at IS NULL AND f.project_id IN (SELECT id FROM family)`+mutedTriage+`
				 GROUP BY f.project_id, f.vuln_id)
			SELECT p.project_id, fa.active, p.rank, count(*), count(*) FILTER (WHERE p.kev), max(p.risk)
			  FROM pairs p JOIN family fa ON fa.id = p.project_id
			 GROUP BY p.project_id, fa.active, p.rank`, hostID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var active bool
			var rank, n, kev int
			var risk float64
			if err := rows.Scan(&id, &active, &rank, &n, &kev, &risk); err != nil {
				return err
			}
			sev := rankSeverity(rank)
			per := out.Host
			if id != hostID {
				var ok bool
				if per, ok = out.Children[id]; !ok {
					per = newPerimeter()
				}
			}
			per.Open.BySeverity[sev] += n
			per.Open.KEV += kev
			per.MaxRisk = math.Max(per.MaxRisk, risk)
			if id == hostID {
				out.Host = per
			} else {
				out.Children[id] = per
			}
			if active {
				out.Total.Open.BySeverity[sev] += n
				out.Total.Open.KEV += kev
				out.Total.MaxRisk = math.Max(out.Total.MaxRisk, risk)
			}
		}
		return rows.Err()
	})
	return out, wrap("constats d'un hôte et de ses conteneurs", err)
}

func newPerimeter() Perimeter { return Perimeter{Open: newCounts()} }
