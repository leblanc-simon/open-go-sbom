package benchdata

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// TeamParams dimensionne les compléments du lot 2 (recette de T18) : équipes, hôtes et
// conteneurs enfants, décisions de triage.
type TeamParams struct {
	Teams               int // équipes, « Général » comprise ; les projets y sont répartis
	Hosts               int // projets hôtes ajoutés
	ContainersPerHost   int // conteneurs enfants par hôte
	ContainerComponents int // composants par ensemble d'un hôte ou d'un conteneur
	TriageEvery         int // un constat ouvert sur TriageEvery reçoit une décision
}

// ReferenceTeams est le complément de référence : 10 équipes, 50 hôtes portant chacun
// 10 conteneurs (550 projets de plus, 200 composants chacun, soit 110 000 liens), une
// décision de triage pour un constat ouvert sur dix.
func ReferenceTeams() TeamParams {
	return TeamParams{Teams: 10, Hosts: 50, ContainersPerHost: 10, ContainerComponents: 200, TriageEvery: 10}
}

// TeamStats décrit le complément produit.
type TeamStats struct {
	// Teams liste les équipes dans l'ordre de répartition : Teams[0] est « Général ».
	Teams      []uuid.UUID
	Hosts      int
	Containers int
	Links      int
	Findings   int
	Decisions  int
	Duration   time.Duration
}

func (p TeamParams) validate() error {
	if p.Teams < 1 || p.Hosts < 0 || p.ContainersPerHost < 0 || p.ContainerComponents < 1 || p.TriageEvery < 1 {
		return errors.New("benchdata: paramètres d'équipes invalides")
	}
	return nil
}

// AddTeamsAndContainers complète un jeu produit par Generate (paramètres p) : équipes
// entre lesquelles les dépôts sont répartis (p-<n> dans l'équipe n mod Teams), hôtes h-<n>
// répartis de même, conteneurs enfants dans l'équipe de leur hôte, avec inventaire,
// constats et analyses, puis décisions de triage de projet (non affecté, faux positif,
// affecté, risque accepté, à parts égales) et statut effectif des constats décidés.
func AddTeamsAndContainers(ctx context.Context, pool *db.Pool, org tenant.OrgID, p Params, tp TeamParams) (TeamStats, error) {
	if err := tp.validate(); err != nil {
		return TeamStats{}, err
	}
	start := time.Now()
	// Rang de chaque équipe : « Général » (identifiant de l'organisation) d'abord.
	const ranked = `(SELECT id, row_number() OVER (ORDER BY id <> org_id, name) - 1 AS k FROM teams)`
	steps := []step{
		{"équipes", `INSERT INTO teams (org_id, id, name) SELECT $1, gen_random_uuid(), 'Équipe ' || g FROM generate_series(2, $2) g`,
			[]any{org, tp.Teams}},
		{"répartition des dépôts", `UPDATE projects p SET team_id = t.id FROM ` + ranked + ` t
			WHERE p.kind = 'repo' AND t.k = substr(p.slug, 3)::int % $1`, []any{tp.Teams}},
		{"hôtes", `INSERT INTO projects (org_id, id, kind, slug, name, team_id)
			SELECT $1, gen_random_uuid(), 'host', 'h-' || g, 'Hôte ' || g, t.id
			  FROM generate_series(1, $2) g JOIN ` + ranked + ` t ON t.k = g % $3`, []any{org, tp.Hosts, tp.Teams}},
		{"références des hôtes", `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
			SELECT org_id, gen_random_uuid(), id, 'host', 'host', slug || '.bench.test' FROM projects WHERE kind = 'host'`, nil},
		{"conteneurs", `INSERT INTO projects (org_id, id, kind, slug, name, team_id, parent_id, parent_kind, container_key, seen_at)
			SELECT h.org_id, gen_random_uuid(), 'container', h.slug || '-c' || j, h.name || ' / app-' || j || '/web', h.team_id,
			       h.id, 'host', 'app-' || j || '/web', now() - interval '1 hour'
			  FROM projects h CROSS JOIN generate_series(1, $1) j WHERE h.kind = 'host'`, []any{tp.ContainersPerHost}},
		{"références des conteneurs", `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
			SELECT org_id, gen_random_uuid(), id, 'container', 'container', container_key FROM projects WHERE kind = 'container'`, nil},
	}
	steps = append(steps, inventorySteps(org, tp.ContainerComponents, p)...)
	steps = append(steps,
		step{"décisions de triage", `INSERT INTO triage_decisions (org_id, id, scope, project_id, vuln_id, purl, purl_base, action, status,
			                               justification, comment, expires_on, author_label, created_at)
			SELECT f.org_id, gen_random_uuid(), 'project', f.project_id, f.vuln_id, c.purl, c.purl_base, 'set', st.status,
			       CASE st.status WHEN 'not_affected' THEN 'component_not_present' END, 'Décision synthétique',
			       CASE st.status WHEN 'risk_accepted' THEN current_date + 90 END, 'system', now()
			  FROM findings f
			  JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
			  CROSS JOIN LATERAL (SELECT (ARRAY['not_affected', 'false_positive', 'affected', 'risk_accepted'])
			                             [abs(hashtext(f.id::text)) % 4 + 1] AS status) st
			 WHERE f.status = 'open' AND abs(hashtext(f.id::text || 'triage')) % $1 = 0`, []any{tp.TriageEvery}},
		step{"statut de triage", `UPDATE findings f SET triage_status = d.status, triage_decision_id = d.id
			  FROM triage_decisions d JOIN components c ON c.org_id = d.org_id AND c.purl = d.purl
			 WHERE f.org_id = d.org_id AND f.project_id = d.project_id AND f.vuln_id = d.vuln_id AND f.component_id = c.id`, nil},
	)
	err := pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		for _, s := range steps {
			if _, err := tx.ExecContext(ctx, s.query, s.args...); err != nil {
				return fmt.Errorf("%s : %w", s.what, err)
			}
		}
		return nil
	})
	if err != nil {
		return TeamStats{}, fmt.Errorf("benchdata: équipes et conteneurs : %w", err)
	}
	st := TeamStats{Duration: time.Since(start)}
	err = pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM `+ranked+` t ORDER BY k`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			st.Teams = append(st.Teams, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM projects WHERE kind = 'host'),
			(SELECT count(*) FROM projects WHERE kind = 'container'),
			(SELECT count(*) FROM component_set_items), (SELECT count(*) FROM findings), (SELECT count(*) FROM triage_decisions)`).
			Scan(&st.Hosts, &st.Containers, &st.Links, &st.Findings, &st.Decisions)
	}, db.ReadOnly())
	return st, err
}

// String résume le complément pour les journaux de mesure.
func (s TeamStats) String() string {
	return strings.Join([]string{
		fmt.Sprintf("%d équipes", len(s.Teams)), fmt.Sprintf("%d hôtes", s.Hosts), fmt.Sprintf("%d conteneurs", s.Containers),
		fmt.Sprintf("%d liens au total", s.Links), fmt.Sprintf("%d constats au total", s.Findings),
		fmt.Sprintf("%d décisions de triage", s.Decisions), fmt.Sprintf("ajouté en %s", s.Duration.Round(time.Millisecond)),
	}, ", ")
}
