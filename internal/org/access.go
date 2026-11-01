package org

import (
	"context"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/tenant"
)

// ErrNoAccess : organisation inconnue, archivée, ou dont le compte n'est pas membre (la
// garde répond 404 dans les trois cas).
var ErrNoAccess = crossorg.ErrNoAccess

// Access établit l'accès de userID à l'organisation de slug, pour les gardes de
// l'interface et de l'API : l'organisation et le rôle d'organisation viennent de crossorg
// (crossorg.ErrNoAccess si l'organisation est inconnue, archivée, ou si le compte n'en est
// pas membre), les rôles d'équipe d'une lecture dans InOrg, sous la RLS.
func (s *Service) Access(ctx context.Context, slug string, userID int64) (tenant.Access, error) {
	acc, err := crossorg.Access(ctx, s.pool.DB(), slug, userID)
	if err != nil {
		return tenant.Access{}, err
	}
	acc.UserID = userID
	acc.Teams = map[uuid.UUID]tenant.TeamRole{}
	err = s.pool.InOrg(ctx, acc.Org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT team_id, role FROM team_members WHERE org_id = $1 AND user_id = $2`,
			tx.OrgID(), userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var team uuid.UUID
			var role string
			if err := rows.Scan(&team, &role); err != nil {
				return err
			}
			r, err := tenant.ParseTeamRole(role)
			if err != nil {
				return err
			}
			acc.Teams[team] = r
		}
		return rows.Err()
	}, db.ReadOnly())
	if err != nil {
		return tenant.Access{}, wrap("rôles d'équipe", err)
	}
	return acc, nil
}
