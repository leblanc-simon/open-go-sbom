package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// EnrollmentToken est un jeton d'inscription d'agents serveur, sans son secret.
type EnrollmentToken struct {
	ID          uuid.UUID
	PublicID    string
	Name        string
	ExpiresAt   time.Time
	MaxUses     int
	Uses        int
	Labels      project.Labels
	ProjectSlug string // projet de serveur à rattacher ; vide : un projet est créé par hôte
	ProjectName string
	TeamID      uuid.UUID // équipe des projets créés et des agents inscrits
	TeamName    string
	CreatedAt   time.Time
	CreatedBy   string
	LastUsedAt  *time.Time
	RevokedAt   *time.Time
}

// Prefix est le début affichable du jeton.
func (t EnrollmentToken) Prefix() string { return DisplayPrefix(KindEnrollment, t.PublicID) }

// UsableAt indique si le jeton accepte encore une inscription à l'instant now.
func (t EnrollmentToken) UsableAt(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt) && t.Uses < t.MaxUses
}

// Durées de validité proposées pour un jeton d'inscription, en heures.
var EnrollmentLifetimes = []int{1, 24, 24 * 7, 24 * 30}

// DefaultEnrollmentLifetime est la durée proposée par défaut, en heures.
const DefaultEnrollmentLifetime = 24

// MaxEnrollmentUses borne le nombre d'usages d'un jeton d'inscription.
const MaxEnrollmentUses = 10000

// EnrollmentInput est la saisie d'un jeton d'inscription.
type EnrollmentInput struct {
	Name          string
	LifetimeHours int
	MaxUses       int
	Labels        project.Labels
	// ProjectSlug désigne un projet de serveur existant à rattacher (un seul usage utile) ;
	// vide, chaque inscription crée le projet de son hôte. Le projet doit être de l'équipe.
	ProjectSlug string
	// TeamID est l'équipe des projets créés et des agents inscrits (obligatoire).
	TeamID uuid.UUID
}

func enrollmentEvent(action audit.Action, t EnrollmentToken, details map[string]string) audit.Event {
	d := map[string]string{"prefix": t.Prefix()}
	for k, v := range details {
		d[k] = v
	}
	return audit.Event{Action: action, TargetType: "enrollment_token", TargetID: t.ID.String(), TargetLabel: t.Name, Details: d}
}

// CreateEnrollment crée un jeton d'inscription ; son secret n'est renvoyé qu'ici.
func (s *Service) CreateEnrollment(ctx context.Context, actor audit.Actor, org tenant.OrgID, in EnrollmentInput) (EnrollmentToken, IssuedToken, error) {
	name, err := validName(in.Name)
	if err != nil {
		return EnrollmentToken{}, IssuedToken{}, err
	}
	valid := false
	for _, h := range EnrollmentLifetimes {
		valid = valid || h == in.LifetimeHours
	}
	if !valid {
		return EnrollmentToken{}, IssuedToken{}, invalid("expires_in", KeyExpiryInvalid)
	}
	if in.MaxUses < 1 || in.MaxUses > MaxEnrollmentUses {
		return EnrollmentToken{}, IssuedToken{}, invalid("max_uses", KeyMaxUsesInvalid)
	}
	if in.TeamID == uuid.Nil {
		return EnrollmentToken{}, IssuedToken{}, invalid("team", KeyTeamInvalid)
	}
	if in.Labels == nil {
		in.Labels = project.Labels{}
	}
	if err := in.Labels.Validate(); err != nil {
		return EnrollmentToken{}, IssuedToken{}, err
	}
	labels, err := json.Marshal(in.Labels)
	if err != nil {
		return EnrollmentToken{}, IssuedToken{}, err
	}
	issued, err := NewToken(KindEnrollment)
	if err != nil {
		return EnrollmentToken{}, IssuedToken{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return EnrollmentToken{}, IssuedToken{}, err
	}
	t := EnrollmentToken{ID: id, PublicID: issued.PublicID, Name: name, MaxUses: in.MaxUses, Labels: in.Labels,
		ExpiresAt: s.Now().Add(time.Duration(in.LifetimeHours) * time.Hour), TeamID: in.TeamID}
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		err := tx.QueryRowContext(ctx, `SELECT name FROM teams WHERE id = $1`, in.TeamID).Scan(&t.TeamName)
		if errors.Is(err, sql.ErrNoRows) {
			return invalid("team", KeyTeamInvalid)
		}
		if err != nil {
			return err
		}
		var projectID uuid.NullUUID
		if in.ProjectSlug != "" {
			var archived bool
			var team uuid.UUID
			err := tx.QueryRowContext(ctx, `SELECT id, name, archived_at IS NOT NULL, team_id FROM projects WHERE slug = $1 AND kind = 'host'`,
				in.ProjectSlug).Scan(&projectID, &t.ProjectName, &archived, &team)
			if errors.Is(err, sql.ErrNoRows) || archived {
				return invalid("project", KeyProjectNotHost)
			}
			if err != nil {
				return err
			}
			if team != in.TeamID {
				return invalid("project", KeyTeamMismatch)
			}
			t.ProjectSlug = in.ProjectSlug
		}
		err = tx.QueryRowContext(ctx, `
			INSERT INTO enrollment_tokens (org_id, id, public_id, secret_hash, name, expires_at, max_uses, labels, project_id,
			                               created_by, team_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING created_at`,
			tx.OrgID(), id, issued.PublicID, issued.Hash[:], name, t.ExpiresAt, in.MaxUses, labels, projectID,
			nullUser(actor.UserID), in.TeamID).Scan(&t.CreatedAt)
		if err != nil {
			return err
		}
		details := map[string]string{"max_uses": strconv.Itoa(in.MaxUses), "expires_at": t.ExpiresAt.Format(time.RFC3339),
			"team": t.TeamName}
		if t.ProjectSlug != "" {
			details["project"] = t.ProjectSlug
		}
		return audit.RecordOrg(ctx, tx, actor, enrollmentEvent(audit.EnrollmentTokenCreated, t, details))
	})
	if err != nil {
		return EnrollmentToken{}, IssuedToken{}, wrap("création d'un jeton d'inscription", err)
	}
	return t, issued, nil
}

// EnrollmentListMax borne la liste des jetons d'inscription.
const EnrollmentListMax = 100

// Enrollments renvoie les jetons d'inscription des équipes visibles, les utilisables
// d'abord puis les plus récents (EnrollmentListMax au plus).
func (s *Service) Enrollments(ctx context.Context, org tenant.OrgID, vis tenant.Visibility) ([]EnrollmentToken, error) {
	var out []EnrollmentToken
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT t.id, t.public_id, t.name, t.expires_at, t.max_uses, t.uses, t.labels, coalesce(p.slug, ''),
			       coalesce(p.name, ''), t.created_at, coalesce(u.email, ''), t.last_used_at, t.revoked_at, t.team_id, tm.name
			  FROM enrollment_tokens t
			  JOIN teams tm ON tm.org_id = t.org_id AND tm.id = t.team_id
			  LEFT JOIN projects p ON p.org_id = t.org_id AND p.id = t.project_id
			  LEFT JOIN users u ON u.id = t.created_by
			 WHERE lotor_team_visible(t.team_id)
			 ORDER BY (t.revoked_at IS NULL AND t.expires_at > $1 AND t.uses < t.max_uses) DESC, t.created_at DESC, t.id DESC
			 LIMIT $2`, s.Now(), EnrollmentListMax)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t EnrollmentToken
			var labels []byte
			var used, revoked sql.NullTime
			if err := rows.Scan(&t.ID, &t.PublicID, &t.Name, &t.ExpiresAt, &t.MaxUses, &t.Uses, &labels, &t.ProjectSlug,
				&t.ProjectName, &t.CreatedAt, &t.CreatedBy, &used, &revoked, &t.TeamID, &t.TeamName); err != nil {
				return err
			}
			if err := json.Unmarshal(labels, &t.Labels); err != nil {
				return err
			}
			t.LastUsedAt, t.RevokedAt = timePtr(used), timePtr(revoked)
			out = append(out, t)
		}
		return rows.Err()
	}, db.ReadOnly(), db.Visible(vis))
	return out, wrap("liste des jetons d'inscription", err)
}

// EnrollmentTeam renvoie l'équipe d'un jeton d'inscription ; ErrNotFound sinon.
func (s *Service) EnrollmentTeam(ctx context.Context, org tenant.OrgID, id uuid.UUID) (uuid.UUID, error) {
	var team uuid.UUID
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		err := tx.QueryRowContext(ctx, `SELECT team_id FROM enrollment_tokens WHERE id = $1`, id).Scan(&team)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}, db.ReadOnly())
	return team, wrap("équipe d'un jeton d'inscription", err)
}

// RevokeEnrollment révoque un jeton d'inscription.
func (s *Service) RevokeEnrollment(ctx context.Context, actor audit.Actor, org tenant.OrgID, id uuid.UUID) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var t EnrollmentToken
		var revoked sql.NullTime
		err := tx.QueryRowContext(ctx, `SELECT id, public_id, name, revoked_at FROM enrollment_tokens WHERE id = $1 FOR UPDATE`, id).
			Scan(&t.ID, &t.PublicID, &t.Name, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if revoked.Valid {
			return invalid("token", KeyTokenRevoked)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET revoked_at = $2, revoked_by = $3 WHERE id = $1`,
			id, s.Now(), nullUser(actor.UserID)); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, enrollmentEvent(audit.EnrollmentTokenRevoked, t, nil))
	})
	return wrap("révocation d'un jeton d'inscription", err)
}
