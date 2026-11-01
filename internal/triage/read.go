package triage

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// HistoryEntry est une ligne de l'historique des décisions d'un constat.
type HistoryEntry struct {
	Decision
	// Current : décision courante de sa clé (elle peut être retirée).
	Current bool
	// Applied : décision qui donne le statut effectif du constat.
	Applied bool
}

// History renvoie, de la plus récente à la plus ancienne, les décisions qui concernent un
// constat d'un projet : celles du projet pour son composant, et celles de l'organisation
// pour sa famille dont la plage contient sa version. ErrNotFound si le constat n'est pas
// du projet.
func (s *Service) History(ctx context.Context, org tenant.OrgID, projectID, findingID uuid.UUID) (out []HistoryEntry, err error) {
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		t, err := target(ctx, tx, projectID, findingID)
		if err != nil {
			return err
		}
		p := pair{t.Target.PURLBase, t.Target.VulnID}
		logs, err := decisionsFor(ctx, tx, []pair{p})
		if err != nil {
			return err
		}
		log := logs[p]
		current := map[uuid.UUID]bool{}
		for _, c := range Current(log) {
			current[c.ID] = true
		}
		for _, d := range log {
			if !s.resolver.Applies(d, t.Target) {
				continue
			}
			out = append(out, HistoryEntry{Decision: d, Current: current[d.ID] && d.Action != ActionWithdraw,
				Applied: d.ID == t.Decision})
		}
		slices.SortFunc(out, func(a, b HistoryEntry) int {
			if later(a.Decision, b.Decision) {
				return -1
			}
			if later(b.Decision, a.Decision) {
				return 1
			}
			return 0
		})
		return nil
	}, db.ReadOnly())
	return out, wrapNotFound(err)
}

// PairCount renvoie le nombre de constats ouverts de l'organisation, tous projets
// confondus, pour une famille de composants et une vulnérabilité : la portée d'une
// décision d'organisation. Réservé aux administrateurs de l'organisation (il compte
// aussi les projets des autres équipes).
func (s *Service) PairCount(ctx context.Context, org tenant.OrgID, purlBase, vulnID string) (n int, err error) {
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM findings f JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
			 WHERE c.purl_base = $1 AND f.vuln_id = $2 AND f.status = 'open'`, purlBase, vulnID).Scan(&n)
	}, db.ReadOnly())
	return n, wrap("portée d'une décision d'organisation", err)
}

// OrgDecisionsMax borne la liste des décisions d'organisation.
const OrgDecisionsMax = 500

// OrgDecision est une décision d'organisation courante et le nombre de constats ouverts
// dont elle donne le statut effectif.
type OrgDecision struct {
	Decision
	Findings int
}

// OrgDecisions renvoie les décisions d'organisation courantes, de la plus récente à la
// plus ancienne (OrgDecisionsMax au plus). Réservé aux administrateurs de l'organisation.
func (s *Service) OrgDecisions(ctx context.Context, org tenant.OrgID) (out []OrgDecision, err error) {
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		log, err := queryDecisions(ctx, tx, `SELECT `+decisionColumns+` FROM triage_decisions WHERE scope = 'org'`)
		if err != nil {
			return err
		}
		cur := Current(log)
		if len(cur) > OrgDecisionsMax {
			cur = cur[:OrgDecisionsMax]
		}
		ids := make([]uuid.UUID, len(cur))
		for i, d := range cur {
			ids[i] = d.ID
		}
		counts := map[uuid.UUID]int{}
		rows, err := tx.QueryContext(ctx, `SELECT triage_decision_id, count(*) FROM findings
			 WHERE triage_decision_id = ANY($1::uuid[]) AND status = 'open' GROUP BY triage_decision_id`, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				return err
			}
			counts[id] = n
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, d := range cur {
			out = append(out, OrgDecision{Decision: d, Findings: counts[d.ID]})
		}
		return nil
	}, db.ReadOnly())
	return out, wrap("décisions de l'organisation", err)
}
