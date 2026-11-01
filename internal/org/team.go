package org

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// Clés de validation des équipes.
const (
	KeyTeamNameInvalid   = "validation.team_name_invalid"
	KeyTeamNameTaken     = "validation.team_name_taken"
	KeyTeamHasProjects   = "validation.team_has_projects"
	KeyTeamLimit         = "validation.team_limit"
	KeyTeamRoleInvalid   = "validation.team_role_invalid"
	KeyTeamMemberExists  = "validation.team_member_exists"
	KeyNotOrgMember      = "validation.team_member_not_org_member"
	KeyInvitationLimit   = "validation.invitation_limit"
	KeyInvitationUnknown = "validation.invitation_unknown"
)

// ValidationKeys liste les clés de validation du paquet (tests de traduction).
func ValidationKeys() []string {
	return []string{KeySlugInvalid, KeySlugTaken, KeyNameInvalid, KeyLanguage, KeyRoleInvalid, KeyMemberExists,
		KeyUnknownAccount, KeyLastOrgAdmin, KeyTeamNameInvalid, KeyTeamNameTaken, KeyTeamHasProjects, KeyTeamLimit,
		KeyTeamRoleInvalid, KeyTeamMemberExists, KeyNotOrgMember, KeyInvitationLimit, KeyInvitationUnknown}
}

// Bornes des équipes : nombre d'équipes par organisation, de membres listés par équipe.
const (
	MaxTeams       = 500
	MaxTeamMembers = 1000
)

// Team est une équipe d'une organisation.
type Team struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
	Members   int
	Projects  int // projets actifs
}

// TeamMember est l'appartenance d'un membre de l'organisation à une équipe.
type TeamMember struct {
	UserID   int64
	Email    string
	Active   bool
	Role     tenant.TeamRole
	JoinedAt time.Time
}

func teamEvent(action audit.Action, t Team, details map[string]string) audit.Event {
	return audit.Event{Action: action, TargetType: "team", TargetID: t.ID.String(), TargetLabel: t.Name, Details: details}
}

const teamColumns = `t.id, t.name, t.created_at,
	(SELECT count(*) FROM team_members m WHERE m.org_id = t.org_id AND m.team_id = t.id),
	(SELECT count(*) FROM projects p WHERE p.org_id = t.org_id AND p.team_id = t.id AND p.archived_at IS NULL)`

func scanTeam(row interface{ Scan(...any) error }) (Team, error) {
	var t Team
	err := row.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.Members, &t.Projects)
	return t, err
}

// Teams renvoie, par nom, les équipes visibles (toutes pour un administrateur
// d'organisation, celles dont le compte est membre sinon).
func (s *Service) Teams(ctx context.Context, org tenant.OrgID, vis tenant.Visibility) ([]Team, error) {
	var out []Team
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+teamColumns+` FROM teams t
			 WHERE lotor_team_visible(t.id) ORDER BY lower(t.name), t.id LIMIT $1`, MaxTeams)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTeam(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	}, db.ReadOnly(), db.Visible(vis))
	return out, wrap("liste des équipes", err)
}

// Team renvoie une équipe visible ; ErrNotFound sinon (inconnue, d'une autre
// organisation ou invisible).
func (s *Service) Team(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, id uuid.UUID) (Team, error) {
	var t Team
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		t, err = scanTeam(tx.QueryRowContext(ctx, `SELECT `+teamColumns+` FROM teams t
			 WHERE t.id = $1 AND lotor_team_visible(t.id)`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return t, wrap("lecture d'une équipe", err)
}

func validTeamName(name string) (string, error) {
	n, err := validName(name)
	if err != nil {
		return "", invalid("name", KeyTeamNameInvalid)
	}
	return n, nil
}

// insertTeam crée une équipe dans la transaction de l'appelant.
func insertTeam(ctx context.Context, tx *db.OrgTx, actor audit.Actor, name string) (Team, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return Team{}, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM teams`).Scan(&n); err != nil {
		return Team{}, err
	}
	if n >= MaxTeams {
		return Team{}, invalid("name", KeyTeamLimit)
	}
	var createdBy *int64
	if actor.UserID != 0 {
		createdBy = &actor.UserID
	}
	t := Team{ID: id, Name: name}
	err = tx.QueryRowContext(ctx, `INSERT INTO teams (org_id, id, name, created_by) VALUES ($1, $2, $3, $4) RETURNING created_at`,
		tx.OrgID(), id, name, createdBy).Scan(&t.CreatedAt)
	if isUnique(err) {
		return Team{}, invalid("name", KeyTeamNameTaken)
	}
	if err != nil {
		return Team{}, err
	}
	return t, audit.RecordOrg(ctx, tx, actor, teamEvent(audit.TeamCreated, t, nil))
}

// CreateTeam crée une équipe.
func (s *Service) CreateTeam(ctx context.Context, actor audit.Actor, org tenant.OrgID, name string) (Team, error) {
	name, err := validTeamName(name)
	if err != nil {
		return Team{}, err
	}
	var t Team
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		// Verrou de l'organisation : le plafond d'équipes tient sous des créations simultanées.
		if _, err := getOrg(ctx, tx, true); err != nil {
			return err
		}
		var err error
		t, err = insertTeam(ctx, tx, actor, name)
		return err
	})
	return t, wrap("création d'une équipe", err)
}

func lockTeam(ctx context.Context, tx *db.OrgTx, id uuid.UUID) (Team, error) {
	t, err := scanTeam(tx.QueryRowContext(ctx, `SELECT `+teamColumns+` FROM teams t WHERE t.id = $1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Team{}, ErrNotFound
	}
	return t, err
}

// RenameTeam renomme une équipe.
func (s *Service) RenameTeam(ctx context.Context, actor audit.Actor, org tenant.OrgID, id uuid.UUID, name string) error {
	name, err := validTeamName(name)
	if err != nil {
		return err
	}
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		t, err := lockTeam(ctx, tx, id)
		if err != nil {
			return err
		}
		if t.Name == name {
			return nil
		}
		_, err = tx.ExecContext(ctx, `UPDATE teams SET name = $2 WHERE id = $1`, id, name)
		if isUnique(err) {
			return invalid("name", KeyTeamNameTaken)
		}
		if err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, teamEvent(audit.TeamRenamed, t, map[string]string{"from": t.Name, "to": name}))
	})
	return wrap("renommage d'une équipe", err)
}

// DeleteTeam supprime une équipe sans projet (archivés compris) : ses membres la
// quittent, ses agents deviennent des agents d'organisation et ses jetons d'inscription
// disparaissent.
func (s *Service) DeleteTeam(ctx context.Context, actor audit.Actor, org tenant.OrgID, id uuid.UUID) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		t, err := lockTeam(ctx, tx, id)
		if err != nil {
			return err
		}
		var projects int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM projects WHERE team_id = $1`, id).Scan(&projects); err != nil {
			return err
		}
		if projects > 0 {
			return invalid("team", KeyTeamHasProjects)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM teams WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, teamEvent(audit.TeamDeleted, t, map[string]string{"members": strconv.Itoa(t.Members)}))
	})
	return wrap("suppression d'une équipe", err)
}

func scanTeamMember(row interface{ Scan(...any) error }) (TeamMember, error) {
	var m TeamMember
	var active int
	var role string
	if err := row.Scan(&m.UserID, &m.Email, &active, &role, &m.JoinedAt); err != nil {
		return TeamMember{}, err
	}
	m.Active = active == 1
	var err error
	m.Role, err = tenant.ParseTeamRole(role)
	return m, err
}

// TeamMembers renvoie les membres d'une équipe, par e-mail (MaxTeamMembers au plus).
func (s *Service) TeamMembers(ctx context.Context, org tenant.OrgID, team uuid.UUID) ([]TeamMember, error) {
	var out []TeamMember
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT m.user_id, u.email, u.is_active, m.role, m.created_at
			  FROM team_members m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND m.team_id = $2 ORDER BY u.email LIMIT $3`, tx.OrgID(), team, MaxTeamMembers)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scanTeamMember(rows)
			if err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("membres d'une équipe", err)
}

func teamMemberEvent(action audit.Action, t Team, userID int64, email string, details map[string]string) audit.Event {
	if details == nil {
		details = map[string]string{}
	}
	details["team"] = t.Name
	return audit.Event{Action: action, TargetType: "member", TargetID: strconv.FormatInt(userID, 10), TargetLabel: email, Details: details}
}

// AddTeamMember ajoute à une équipe un membre de l'organisation, désigné par son e-mail.
// Un compte qui n'est pas membre de l'organisation est refusé (KeyNotOrgMember), quel que
// soit son état : la liste des membres est déjà connue de qui gère une équipe.
func (s *Service) AddTeamMember(ctx context.Context, actor audit.Actor, org tenant.OrgID, team uuid.UUID, email string, role tenant.TeamRole) error {
	if _, err := tenant.ParseTeamRole(string(role)); err != nil {
		return invalid("role", KeyTeamRoleInvalid)
	}
	e, err := account.NormalizeEmail(email)
	if err != nil {
		return err
	}
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		t, err := lockTeam(ctx, tx, team)
		if err != nil {
			return err
		}
		var userID int64
		err = tx.QueryRowContext(ctx, `SELECT m.user_id FROM org_memberships m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND u.email = $2`, tx.OrgID(), e).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			return invalid("email", KeyNotOrgMember)
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO team_members (org_id, team_id, user_id, role) VALUES ($1, $2, $3, $4)`,
			tx.OrgID(), team, userID, string(role))
		if isUnique(err) {
			return invalid("email", KeyTeamMemberExists)
		}
		if err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, teamMemberEvent(audit.TeamMemberAdded, t, userID, e, map[string]string{"role": string(role)}))
	})
	return wrap("ajout d'un membre à une équipe", err)
}

func lockTeamMember(ctx context.Context, tx *db.OrgTx, team uuid.UUID, userID int64) (Team, TeamMember, error) {
	t, err := lockTeam(ctx, tx, team)
	if err != nil {
		return Team{}, TeamMember{}, err
	}
	m, err := scanTeamMember(tx.QueryRowContext(ctx, `
		SELECT m.user_id, u.email, u.is_active, m.role, m.created_at
		  FROM team_members m JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 AND m.team_id = $2 AND m.user_id = $3 FOR UPDATE OF m`, tx.OrgID(), team, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Team{}, TeamMember{}, ErrNotFound
	}
	return t, m, err
}

// SetTeamMemberRole change le rôle d'un membre dans une équipe.
func (s *Service) SetTeamMemberRole(ctx context.Context, actor audit.Actor, org tenant.OrgID, team uuid.UUID, userID int64, role tenant.TeamRole) error {
	if _, err := tenant.ParseTeamRole(string(role)); err != nil {
		return invalid("role", KeyTeamRoleInvalid)
	}
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		t, m, err := lockTeamMember(ctx, tx, team, userID)
		if err != nil {
			return err
		}
		if m.Role == role {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE team_members SET role = $1 WHERE org_id = $2 AND team_id = $3 AND user_id = $4`,
			string(role), tx.OrgID(), team, userID); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, teamMemberEvent(audit.TeamMemberRoleChanged, t, userID, m.Email,
			map[string]string{"from": string(m.Role), "to": string(role)}))
	})
	return wrap("changement de rôle d'équipe", err)
}

// RemoveTeamMember retire un membre d'une équipe (il reste membre de l'organisation).
func (s *Service) RemoveTeamMember(ctx context.Context, actor audit.Actor, org tenant.OrgID, team uuid.UUID, userID int64) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		t, m, err := lockTeamMember(ctx, tx, team, userID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM team_members WHERE org_id = $1 AND team_id = $2 AND user_id = $3`,
			tx.OrgID(), team, userID); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, teamMemberEvent(audit.TeamMemberRemoved, t, userID, m.Email,
			map[string]string{"role": string(m.Role)}))
	})
	return wrap("retrait d'un membre d'une équipe", err)
}

// TeamMember renvoie l'appartenance de userID à une équipe ; ErrNotFound s'il n'en est
// pas membre.
func (s *Service) TeamMember(ctx context.Context, org tenant.OrgID, team uuid.UUID, userID int64) (TeamMember, error) {
	var m TeamMember
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		m, err = scanTeamMember(tx.QueryRowContext(ctx, `
			SELECT m.user_id, u.email, u.is_active, m.role, m.created_at
			  FROM team_members m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND m.team_id = $2 AND m.user_id = $3`, tx.OrgID(), team, userID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}, db.ReadOnly())
	return m, wrap("lecture d'un membre d'équipe", err)
}
