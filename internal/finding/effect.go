package finding

import (
	"context"
	"database/sql"
	"strings"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// EffectMax borne les constats listés de chaque côté d'un effet sur la sécurité.
const EffectMax = 200

// EffectSide est un instantané comparé : sa référence et son ensemble d'inventaire.
type EffectSide struct {
	SnapshotID uuid.UUID
	RefID      uuid.UUID
	SetID      uuid.UUID
}

// Effect est l'effet sur la sécurité du passage d'un instantané à un autre (ADR 0038) :
// constats introduits (sur un composant que seul le second contient) et résolus (sur un
// composant que seul le premier contient). Une vulnérabilité présente sur les deux
// versions d'un même purl_base n'est ni introduite ni résolue.
type Effect struct {
	Introduced      []Row
	Resolved        []Row
	IntroducedTotal int
	ResolvedTotal   int
	// Pending : le second instantané est l'instantané courant de sa référence et son
	// ensemble n'est pas encore analysé ; les constats introduits peuvent manquer.
	Pending bool
}

// prefixed lit une colonne avant celles d'un constat.
type prefixed struct {
	rows  *sql.Rows
	first any
}

func (p prefixed) Scan(dest ...any) error { return p.rows.Scan(append([]any{p.first}, dest...)...) }

// SnapshotEffect calcule l'effet sur la sécurité du passage de from à to. Les constats
// viennent de la référence de chaque côté : ceux de from sur les composants retirés ou
// remplacés, ceux de to sur les composants ajoutés ou de nouvelle version. Un constat
// résolu parce que la base ne juge plus le composant vulnérable (not_matched) n'est pas
// compté : ce n'était pas une vulnérabilité. Chaque liste est bornée à limit, par risque
// décroissant ; les totaux comptent tout.
func SnapshotEffect(ctx context.Context, tx *db.OrgTx, from, to EffectSide, limit int) (Effect, error) {
	var e Effect
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM ref_current WHERE ref_id = $1 AND snapshot_id = $2)
		   AND NOT EXISTS (SELECT 1 FROM ref_analyses WHERE ref_id = $1 AND set_id = $3)`,
		to.RefID, to.SnapshotID, to.SetID).Scan(&e.Pending)
	if err != nil {
		return Effect{}, wrap("analyse en attente", err)
	}
	if from.SetID == to.SetID {
		return e, nil
	}
	query := `
		WITH r AS (
		    SELECT component_id FROM component_set_items WHERE set_id = $1
		    EXCEPT SELECT component_id FROM component_set_items WHERE set_id = $2
		), a AS (
		    SELECT component_id FROM component_set_items WHERE set_id = $2
		    EXCEPT SELECT component_id FROM component_set_items WHERE set_id = $1
		), fr AS (
		    SELECT f.id, f.vuln_id, c.purl_base FROM findings f
		      JOIN r ON r.component_id = f.component_id
		      JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
		     WHERE f.ref_id = $3 AND f.resolution IS DISTINCT FROM 'not_matched'
		), fa AS (
		    SELECT f.id, f.vuln_id, c.purl_base FROM findings f
		      JOIN a ON a.component_id = f.component_id
		      JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
		     WHERE f.ref_id = $4 AND f.resolution IS DISTINCT FROM 'not_matched'
		), effect AS (
		    SELECT 'resolved' AS side, fr.id FROM fr
		     WHERE NOT EXISTS (SELECT 1 FROM fa WHERE fa.purl_base = fr.purl_base AND fa.vuln_id = fr.vuln_id)
		    UNION ALL
		    SELECT 'introduced', fa.id FROM fa
		     WHERE NOT EXISTS (SELECT 1 FROM fr WHERE fr.purl_base = fa.purl_base AND fr.vuln_id = fa.vuln_id)
		)
		SELECT e.side, ` + rowColumns + strings.Replace(rowFrom, "FROM findings f", "FROM effect e JOIN findings f ON f.id = e.id", 1) + `
		 ORDER BY e.side, f.risk DESC, f.vuln_id, f.id`
	rows, err := tx.QueryContext(ctx, query, from.SetID, to.SetID, from.RefID, to.RefID)
	if err != nil {
		return Effect{}, wrap("effet sur la sécurité", err)
	}
	defer rows.Close()
	for rows.Next() {
		var side string
		r, err := scanRow(prefixed{rows: rows, first: &side})
		if err != nil {
			return Effect{}, wrap("effet sur la sécurité", err)
		}
		if side == "resolved" {
			e.ResolvedTotal++
			if len(e.Resolved) < limit {
				e.Resolved = append(e.Resolved, r)
			}
			continue
		}
		e.IntroducedTotal++
		if len(e.Introduced) < limit {
			e.Introduced = append(e.Introduced, r)
		}
	}
	if err := rows.Err(); err != nil {
		return Effect{}, wrap("effet sur la sécurité", err)
	}
	return e, nil
}

// Effect : voir SnapshotEffect, bornée à EffectMax.
func (s *Service) Effect(ctx context.Context, org tenant.OrgID, from, to EffectSide) (e Effect, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		e, err = SnapshotEffect(ctx, tx, from, to, EffectMax)
		return err
	})
	return e, err
}
