package project

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/pagination"
)

// Ce qui suit sert l'API des agents : un agent ne voit et n'écrit que les projets actifs
// qui lui sont confiés. Les fonctions travaillent dans la transaction InOrg de l'appelant,
// ouverte sur l'organisation du jeton.

// AgentPageMax borne une page de ListForAgent.
const AgentPageMax = 200

type agentCursor struct {
	I uuid.UUID `json:"i"`
}

// ListForAgent renvoie les projets actifs confiés à agentID, avec leurs références
// actives, par ordre de création.
func ListForAgent(ctx context.Context, tx *db.OrgTx, agentID uuid.UUID, cursor string, limit int) (pagination.Page[Project], error) {
	if limit < 1 || limit > AgentPageMax {
		return pagination.Page[Project]{}, &pagination.LimitError{Max: AgentPageMax}
	}
	var after agentCursor
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[Project]{}, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+columns+from+`
		 WHERE p.agent_id = $1 AND p.archived_at IS NULL AND p.id > $2
		 ORDER BY p.id LIMIT $3`, agentID, after.I, limit+1)
	if err != nil {
		return pagination.Page[Project]{}, wrap("projets d'un agent", err)
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return pagination.Page[Project]{}, wrap("projets d'un agent", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[Project]{}, wrap("projets d'un agent", err)
	}
	page, err := pagination.Build(out, limit, func(p Project) any { return agentCursor{I: p.ID} })
	if err != nil {
		return pagination.Page[Project]{}, err
	}
	if err := attachRefs(ctx, tx, page.Items); err != nil {
		return pagination.Page[Project]{}, wrap("références des projets d'un agent", err)
	}
	return page, nil
}

// attachRefs charge en une requête les références actives des projets.
func attachRefs(ctx context.Context, tx *db.OrgTx, projects []Project) error {
	if len(projects) == 0 {
		return nil
	}
	ids := make([]string, len(projects))
	index := make(map[uuid.UUID]int, len(projects))
	for i, p := range projects {
		ids[i], index[p.ID] = p.ID.String(), i
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT project_id, id, kind, name FROM tracked_refs
		 WHERE project_id = ANY($1::uuid[]) AND removed_at IS NULL ORDER BY project_id, kind, name`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var pid uuid.UUID
		var r Ref
		var kind string
		if err := rows.Scan(&pid, &r.ID, &kind, &r.Name); err != nil {
			return err
		}
		r.Kind = RefKind(kind)
		i := index[pid]
		projects[i].Refs = append(projects[i].Refs, r)
	}
	return rows.Err()
}

// RefOfAgent renvoie le projet de la référence active refID si ce projet, actif, est
// confié à agentID ; ErrNotFound sinon, que la référence existe ou non.
func RefOfAgent(ctx context.Context, tx *db.OrgTx, agentID, refID uuid.UUID) (uuid.UUID, error) {
	var projectID uuid.UUID
	err := tx.QueryRowContext(ctx, `
		SELECT p.id FROM tracked_refs r
		  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id
		 WHERE r.id = $1 AND p.agent_id = $2 AND p.archived_at IS NULL AND r.removed_at IS NULL`,
		refID, agentID).Scan(&projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, wrap("référence d'un agent", err)
	}
	return projectID, nil
}

// RefForAgent renvoie la référence active (kind, name) du projet projectID si ce projet,
// actif, est confié à agentID ; ErrNotFound sinon, que le projet existe ou non. Un
// conteneur est confié à l'agent de son hôte, actif lui aussi. C'est le contrôle
// d'écriture des envois d'un agent (T05).
func RefForAgent(ctx context.Context, tx *db.OrgTx, agentID, projectID uuid.UUID, kind RefKind, name string) (Ref, error) {
	r := Ref{Kind: kind, Name: name}
	err := tx.QueryRowContext(ctx, `
		SELECT r.id FROM tracked_refs r
		  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id
		  LEFT JOIN projects h ON h.org_id = p.org_id AND h.id = p.parent_id
		 WHERE p.id = $1 AND coalesce(p.agent_id, h.agent_id) = $2 AND p.archived_at IS NULL AND h.archived_at IS NULL
		   AND r.kind = $3 AND r.name = $4 AND r.removed_at IS NULL`,
		projectID, agentID, string(kind), name).Scan(&r.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return Ref{}, ErrNotFound
	}
	if err != nil {
		return Ref{}, wrap("référence d'un agent", err)
	}
	return r, nil
}
