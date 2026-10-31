package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/pagination"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// ErrNotFound : agent ou jeton inconnu dans l'organisation déclarée.
var ErrNotFound = errors.New("agent: introuvable")

// Kind est la nature d'un agent, la même que celle des projets qu'il alimente.
type Kind string

// Natures d'agents.
const (
	KindHost Kind = "host" // ogsbom-host-agent : un seul hôte
	KindRepo Kind = "repo" // ogsbom-repo-agent : des dépôts confiés depuis l'interface
)

// Kinds renvoie les natures d'agents.
func Kinds() []Kind { return []Kind{KindHost, KindRepo} }

// State est l'état d'un agent vu de l'interface.
type State string

// États d'un agent.
const (
	StatePending  State = "pending"  // aucun contact depuis sa création
	StateActive   State = "active"   // contact récent
	StateSilent   State = "silent"   // aucun contact depuis SilentAfter
	StateDisabled State = "disabled" // désactivé : jetons révoqués, projets retirés
)

// SilentAfter est la durée sans contact au-delà de laquelle un agent est muet. T05
// pourra la fonder sur le dernier instantané plutôt que sur le dernier contact.
const SilentAfter = 72 * time.Hour

// Clés de validation.
const (
	KeyNameInvalid    = "validation.name_invalid"
	KeyNameTaken      = "validation.agent_name_taken"
	KeyExpiryInvalid  = "validation.token_expiry_invalid"
	KeyMaxUsesInvalid = "validation.token_max_uses_invalid"
	KeyAgentDisabled  = "validation.agent_disabled"
	KeyVersionInvalid = "validation.agent_version_invalid"
	KeyProjectNotHost = "validation.enrollment_project_invalid"
	KeyTokenRevoked   = "validation.token_already_revoked"
)

// ValidationKeys liste les clés de validation du paquet (tests de traduction).
func ValidationKeys() []string {
	return []string{KeyNameInvalid, KeyNameTaken, KeyExpiryInvalid, KeyMaxUsesInvalid, KeyAgentDisabled,
		KeyVersionInvalid, KeyProjectNotHost, KeyTokenRevoked}
}

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// Agent est un agent et, pour sa fiche, ses projets et ses jetons.
type Agent struct {
	ID           uuid.UUID
	Kind         Kind
	Name         string
	Version      string
	LastSeenAt   *time.Time
	DisabledAt   *time.Time
	CreatedAt    time.Time
	ProjectCount int
	ActiveTokens int
	Projects     []ProjectRef // Get seulement
	Tokens       []Token      // Get seulement
}

// StateAt renvoie l'état de l'agent à l'instant now.
func (a Agent) StateAt(now time.Time) State { return StateOf(a.LastSeenAt, a.DisabledAt != nil, now) }

// StateOf renvoie l'état d'un agent d'après son dernier contact.
func StateOf(lastSeen *time.Time, disabled bool, now time.Time) State {
	switch {
	case disabled:
		return StateDisabled
	case lastSeen == nil:
		return StatePending
	case now.Sub(*lastSeen) > SilentAfter:
		return StateSilent
	}
	return StateActive
}

// ProjectRef est un projet confié à un agent.
type ProjectRef struct {
	Slug     string
	Name     string
	Archived bool
}

// Token est un jeton d'agent, sans son secret.
type Token struct {
	ID         uuid.UUID
	PublicID   string
	Name       string
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	CreatedBy  string // e-mail de l'auteur, vide si inconnu
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Prefix est le début affichable du jeton.
func (t Token) Prefix() string { return DisplayPrefix(KindAgent, t.PublicID) }

// ActiveAt indique si le jeton est utilisable à l'instant now.
func (t Token) ActiveAt(now time.Time) bool {
	return t.RevokedAt == nil && (t.ExpiresAt == nil || now.Before(*t.ExpiresAt))
}

// Service gère les agents et leurs jetons. Toute lecture et toute écriture passent par
// InOrg ; chaque modification est journalisée dans la même transaction.
type Service struct {
	pool *db.Pool
	now  func() time.Time
}

// Option règle le service.
type Option func(*Service)

// WithClock remplace l'horloge du système (tests d'expiration).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// NewService construit le service.
func NewService(pool *db.Pool, opts ...Option) *Service {
	s := &Service{pool: pool, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Now renvoie l'heure de l'horloge du service.
func (s *Service) Now() time.Time { return s.now().UTC() }

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok || errors.Is(err, ErrNotFound) || isAuthError(err) {
		return err
	}
	return fmt.Errorf("agent: %s : %w", what, err)
}

func pgConstraint(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.ConstraintName
	}
	return ""
}

func validName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || utf8.RuneCountInString(n) > 100 || !utf8.ValidString(n) || strings.ContainsFunc(n, unicode.IsControl) {
		return "", invalid("name", KeyNameInvalid)
	}
	return n, nil
}

// Durées de validité proposées pour un jeton d'agent ; 0 : sans expiration.
var TokenLifetimes = []int{30, 90, 180, 365, 0}

// DefaultTokenLifetime est la durée proposée par défaut, en jours.
const DefaultTokenLifetime = 90

func validLifetime(days int) error {
	for _, d := range TokenLifetimes {
		if d == days {
			return nil
		}
	}
	return invalid("expires_in", KeyExpiryInvalid)
}

func expiry(now time.Time, days int) *time.Time {
	if days == 0 {
		return nil
	}
	t := now.Add(time.Duration(days) * 24 * time.Hour)
	return &t
}

func agentEvent(action audit.Action, a Agent, details map[string]string) audit.Event {
	return audit.Event{Action: action, TargetType: "agent", TargetID: a.ID.String(), TargetLabel: a.Name, Details: details}
}

func newAgent(ctx context.Context, tx *db.OrgTx, kind Kind, name, version string, createdBy int64, seen *time.Time) (Agent, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return Agent{}, err
	}
	var by any
	if createdBy != 0 {
		by = createdBy
	}
	a := Agent{ID: id, Kind: kind, Name: name, Version: version, LastSeenAt: seen}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO agents (org_id, id, kind, name, version, last_seen_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at`,
		tx.OrgID(), id, string(kind), name, version, seen, by).Scan(&a.CreatedAt)
	if pgConstraint(err) == "agents_active_name" {
		return Agent{}, invalid("name", KeyNameTaken)
	}
	return a, err
}

// insertToken enregistre un jeton tiré pour agentID.
func insertToken(ctx context.Context, tx *db.OrgTx, agentID uuid.UUID, name string, expires *time.Time, createdBy int64) (Token, IssuedToken, error) {
	issued, err := NewToken(KindAgent)
	if err != nil {
		return Token{}, IssuedToken{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Token{}, IssuedToken{}, err
	}
	var by any
	if createdBy != 0 {
		by = createdBy
	}
	t := Token{ID: id, PublicID: issued.PublicID, Name: name, ExpiresAt: expires}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO agent_tokens (org_id, id, agent_id, public_id, secret_hash, name, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING created_at`,
		tx.OrgID(), id, agentID, issued.PublicID, issued.Hash[:], name, expires, by).Scan(&t.CreatedAt)
	return t, issued, err
}

func tokenEvent(action audit.Action, a Agent, t Token, details map[string]string) audit.Event {
	d := map[string]string{"agent": a.Name, "prefix": t.Prefix()}
	for k, v := range details {
		d[k] = v
	}
	return audit.Event{Action: action, TargetType: "agent_token", TargetID: t.ID.String(), TargetLabel: t.Name, Details: d}
}

// CreateRepoAgent crée un agent dépôt et son premier jeton, dont le secret n'est renvoyé
// qu'ici.
func (s *Service) CreateRepoAgent(ctx context.Context, actor audit.Actor, org tenant.OrgID, name, tokenName string, lifetimeDays int) (Agent, IssuedToken, error) {
	name, err := validName(name)
	if err != nil {
		return Agent{}, IssuedToken{}, err
	}
	if tokenName, err = validName(tokenName); err != nil {
		return Agent{}, IssuedToken{}, invalid("token_name", KeyNameInvalid)
	}
	if err := validLifetime(lifetimeDays); err != nil {
		return Agent{}, IssuedToken{}, err
	}
	var a Agent
	var issued IssuedToken
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		if a, err = newAgent(ctx, tx, KindRepo, name, "", actor.UserID, nil); err != nil {
			return err
		}
		var t Token
		if t, issued, err = insertToken(ctx, tx, a.ID, tokenName, expiry(s.Now(), lifetimeDays), actor.UserID); err != nil {
			return err
		}
		if err := audit.RecordOrg(ctx, tx, actor, agentEvent(audit.AgentCreated, a, map[string]string{"kind": string(a.Kind)})); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, tokenEvent(audit.AgentTokenCreated, a, t, nil))
	})
	if err != nil {
		return Agent{}, IssuedToken{}, wrap("création d'un agent", err)
	}
	return a, issued, nil
}

const agentColumns = `a.id, a.kind, a.name, a.version, a.last_seen_at, a.disabled_at, a.created_at,
	(SELECT count(*) FROM projects p WHERE p.org_id = a.org_id AND p.agent_id = a.id AND p.archived_at IS NULL),
	(SELECT count(*) FROM agent_tokens t WHERE t.org_id = a.org_id AND t.agent_id = a.id AND t.revoked_at IS NULL
	    AND (t.expires_at IS NULL OR t.expires_at > $1))`

func scanAgent(row interface{ Scan(...any) error }) (Agent, error) {
	var a Agent
	var kind string
	var seen, disabled sql.NullTime
	if err := row.Scan(&a.ID, &kind, &a.Name, &a.Version, &seen, &disabled, &a.CreatedAt, &a.ProjectCount, &a.ActiveTokens); err != nil {
		return Agent{}, err
	}
	a.Kind = Kind(kind)
	a.LastSeenAt, a.DisabledAt = timePtr(seen), timePtr(disabled)
	return a, nil
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func loadAgent(ctx context.Context, tx *db.OrgTx, id uuid.UUID, now time.Time, lock bool) (Agent, error) {
	query := `SELECT ` + agentColumns + ` FROM agents a WHERE a.id = $2`
	if lock {
		query += ` FOR UPDATE`
	}
	a, err := scanAgent(tx.QueryRowContext(ctx, query, now, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
}

// Get renvoie un agent, ses projets et ses jetons (les 100 plus récents).
func (s *Service) Get(ctx context.Context, org tenant.OrgID, id uuid.UUID) (Agent, error) {
	var a Agent
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		if a, err = loadAgent(ctx, tx, id, s.Now(), false); err != nil {
			return err
		}
		if a.Projects, err = agentProjects(ctx, tx, id); err != nil {
			return err
		}
		a.Tokens, err = agentTokens(ctx, tx, id)
		return err
	}, db.ReadOnly())
	return a, wrap("lecture d'un agent", err)
}

func agentProjects(ctx context.Context, tx *db.OrgTx, id uuid.UUID) ([]ProjectRef, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT slug, name, archived_at IS NOT NULL FROM projects WHERE agent_id = $1
		 ORDER BY archived_at IS NOT NULL, lower(name) LIMIT 200`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectRef
	for rows.Next() {
		var p ProjectRef
		if err := rows.Scan(&p.Slug, &p.Name, &p.Archived); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func agentTokens(ctx context.Context, tx *db.OrgTx, id uuid.UUID) ([]Token, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT t.id, t.public_id, t.name, t.expires_at, t.created_at, coalesce(u.email, ''), t.last_used_at, t.revoked_at
		  FROM agent_tokens t LEFT JOIN users u ON u.id = t.created_by
		 WHERE t.agent_id = $1 ORDER BY t.revoked_at IS NOT NULL, t.created_at DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		var expires, used, revoked sql.NullTime
		if err := rows.Scan(&t.ID, &t.PublicID, &t.Name, &expires, &t.CreatedAt, &t.CreatedBy, &used, &revoked); err != nil {
			return nil, err
		}
		t.ExpiresAt, t.LastUsedAt, t.RevokedAt = timePtr(expires), timePtr(used), timePtr(revoked)
		out = append(out, t)
	}
	return out, rows.Err()
}

// Filter restreint une liste d'agents.
type Filter struct {
	Kind     Kind // vide : toutes natures
	Disabled bool // agents désactivés au lieu des autres
}

// DefaultPage et MaxPage bornent une page d'agents.
const (
	DefaultPage = 50
	MaxPage     = 200
)

type listCursor struct {
	N string    `json:"n"`
	I uuid.UUID `json:"i"`
}

// List renvoie une page d'agents, par nom.
func (s *Service) List(ctx context.Context, org tenant.OrgID, f Filter, cursor string, limit int) (pagination.Page[Agent], error) {
	if limit < 1 || limit > MaxPage {
		return pagination.Page[Agent]{}, &pagination.LimitError{Max: MaxPage}
	}
	var after listCursor
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[Agent]{}, err
		}
	}
	type row struct {
		Agent
		sortName string
	}
	var page pagination.Page[Agent]
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT lower(a.name), `+agentColumns+` FROM agents a
			 WHERE (a.disabled_at IS NOT NULL) = $2 AND ($3 = '' OR a.kind = $3)
			   AND ($4 = '' OR (lower(a.name), a.id) > ($4, $5::uuid))
			 ORDER BY lower(a.name), a.id LIMIT $6`,
			s.Now(), f.Disabled, string(f.Kind), after.N, after.I, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			var sortName string
			a, err := scanAgent(scannerFunc(func(dest ...any) error {
				return rows.Scan(append([]any{&sortName}, dest...)...)
			}))
			if err != nil {
				return err
			}
			r.Agent, r.sortName = a, sortName
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		p, err := pagination.Build(out, limit, func(r row) any { return listCursor{N: r.sortName, I: r.ID} })
		if err != nil {
			return err
		}
		page.NextCursor = p.NextCursor
		for _, r := range p.Items {
			page.Items = append(page.Items, r.Agent)
		}
		return nil
	}, db.ReadOnly())
	return page, wrap("liste des agents", err)
}

type scannerFunc func(dest ...any) error

func (f scannerFunc) Scan(dest ...any) error { return f(dest...) }

// RepoAgents renvoie les agents dépôt actifs (200 au plus), pour confier un dépôt.
func (s *Service) RepoAgents(ctx context.Context, org tenant.OrgID) ([]Agent, error) {
	var out []Agent
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents a
			 WHERE a.kind = 'repo' AND a.disabled_at IS NULL ORDER BY lower(a.name), a.id LIMIT 200`, s.Now())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAgent(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("agents dépôt", err)
}

// CreateToken crée un nouveau jeton pour un agent actif (rotation) ; son secret n'est
// renvoyé qu'ici.
func (s *Service) CreateToken(ctx context.Context, actor audit.Actor, org tenant.OrgID, agentID uuid.UUID, name string, lifetimeDays int) (Token, IssuedToken, error) {
	name, err := validName(name)
	if err != nil {
		return Token{}, IssuedToken{}, err
	}
	if err := validLifetime(lifetimeDays); err != nil {
		return Token{}, IssuedToken{}, err
	}
	var t Token
	var issued IssuedToken
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		a, err := loadAgent(ctx, tx, agentID, s.Now(), true)
		if err != nil {
			return err
		}
		if a.DisabledAt != nil {
			return invalid("agent", KeyAgentDisabled)
		}
		if t, issued, err = insertToken(ctx, tx, a.ID, name, expiry(s.Now(), lifetimeDays), actor.UserID); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, tokenEvent(audit.AgentTokenCreated, a, t, nil))
	})
	if err != nil {
		return Token{}, IssuedToken{}, wrap("création d'un jeton d'agent", err)
	}
	return t, issued, nil
}

// RevokeToken révoque un jeton d'agent : la requête suivante qui le présente est refusée.
func (s *Service) RevokeToken(ctx context.Context, actor audit.Actor, org tenant.OrgID, agentID, tokenID uuid.UUID) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		a, err := loadAgent(ctx, tx, agentID, s.Now(), false)
		if err != nil {
			return err
		}
		var t Token
		var revoked sql.NullTime
		err = tx.QueryRowContext(ctx, `SELECT id, public_id, name, revoked_at FROM agent_tokens
			 WHERE id = $1 AND agent_id = $2 FOR UPDATE`, tokenID, agentID).Scan(&t.ID, &t.PublicID, &t.Name, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if revoked.Valid {
			return invalid("token", KeyTokenRevoked)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_tokens SET revoked_at = $2, revoked_by = $3 WHERE id = $1`,
			tokenID, s.Now(), nullUser(actor.UserID)); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, tokenEvent(audit.AgentTokenRevoked, a, t, nil))
	})
	return wrap("révocation d'un jeton d'agent", err)
}

func nullUser(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// Disable désactive un agent : ses jetons sont révoqués et ses projets lui sont retirés
// (un hôte pourra s'inscrire de nouveau avec un nouvel agent).
func (s *Service) Disable(ctx context.Context, actor audit.Actor, org tenant.OrgID, agentID uuid.UUID) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		a, err := loadAgent(ctx, tx, agentID, s.Now(), true)
		if err != nil {
			return err
		}
		if a.DisabledAt != nil {
			return nil
		}
		now := s.Now()
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET disabled_at = $2 WHERE id = $1`, agentID, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_tokens SET revoked_at = $2, revoked_by = $3
			 WHERE agent_id = $1 AND revoked_at IS NULL`, agentID, now, nullUser(actor.UserID)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE projects SET agent_id = NULL, updated_at = now() WHERE agent_id = $1`, agentID); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, agentEvent(audit.AgentDisabled, a, nil))
	})
	return wrap("désactivation d'un agent", err)
}
