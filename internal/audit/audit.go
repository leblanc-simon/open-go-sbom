package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/pagination"
)

// Action est la nature d'un événement d'audit, « domaine.verbe ». Chacune a sa phrase
// traduite audit.action.<domaine>_<verbe> (Key).
type Action string

// Actions journalisées. Toute nouvelle action s'ajoute ici et dans les traductions.
const (
	LoginSucceeded Action = "auth.login"
	LoginFailed    Action = "auth.login_failed"
	TOTPFailed     Action = "auth.totp_failed"
	TOTPEnrolled   Action = "auth.totp_enrolled"
	Logout         Action = "auth.logout"

	AccountCreated         Action = "account.created"
	AccountDeactivated     Action = "account.deactivated"
	AccountActivated       Action = "account.activated"
	AccountPasswordReset   Action = "account.password_reset"
	AccountPasswordChanged Action = "account.password_changed"
	AccountTOTPReset       Action = "account.totp_reset"
	AccountRoleChanged     Action = "account.role_changed"
	AccountSettingsChanged Action = "account.settings_changed"
	AccountBootstrapped    Action = "account.bootstrapped"
	AccountRescueTOTPReset Action = "account.rescue_totp_reset"
	OrgCreated             Action = "org.created"
	OrgRenamed             Action = "org.renamed"
	OrgLanguageChanged     Action = "org.language_changed"
	OrgArchived            Action = "org.archived"
	OrgUnarchived          Action = "org.unarchived"
	MemberAdded            Action = "member.added"
	MemberRoleChanged      Action = "member.role_changed"
	MemberRemoved          Action = "member.removed"
	ProjectCreated         Action = "project.created"
	ProjectUpdated         Action = "project.updated"
	ProjectArchived        Action = "project.archived"
	ProjectUnarchived      Action = "project.unarchived"
	ProjectAgentChanged    Action = "project.agent_changed"
	AgentCreated           Action = "agent.created"
	AgentEnrolled          Action = "agent.enrolled"
	AgentDisabled          Action = "agent.disabled"
	AgentTokenCreated      Action = "agent_token.created"
	AgentTokenRevoked      Action = "agent_token.revoked"
	EnrollmentTokenCreated Action = "enrollment_token.created"
	EnrollmentTokenRevoked Action = "enrollment_token.revoked"
)

// Actions renvoie toutes les actions connues (tests de traduction).
func Actions() []Action {
	return []Action{
		LoginSucceeded, LoginFailed, TOTPFailed, TOTPEnrolled, Logout,
		AccountCreated, AccountDeactivated, AccountActivated, AccountPasswordReset,
		AccountPasswordChanged, AccountTOTPReset, AccountRoleChanged, AccountSettingsChanged,
		AccountBootstrapped, AccountRescueTOTPReset,
		OrgCreated, OrgRenamed, OrgLanguageChanged, OrgArchived, OrgUnarchived,
		MemberAdded, MemberRoleChanged, MemberRemoved,
		ProjectCreated, ProjectUpdated, ProjectArchived, ProjectUnarchived, ProjectAgentChanged,
		AgentCreated, AgentEnrolled, AgentDisabled, AgentTokenCreated, AgentTokenRevoked,
		EnrollmentTokenCreated, EnrollmentTokenRevoked,
	}
}

// Key renvoie la clé de traduction de la phrase qui décrit l'action.
func (a Action) Key() string { return "audit.action." + strings.ReplaceAll(string(a), ".", "_") }

// Actor est l'auteur d'un événement et le contexte de sa requête. Un acteur sans compte
// (UserID 0) est le système (démarrage) ou un visiteur anonyme (échec de connexion).
type Actor struct {
	UserID    int64
	Email     string
	IP        string
	RequestID string
}

// System est l'acteur des opérations de démarrage (bootstrap, procédure de secours).
var System = Actor{}

// Event est un événement à journaliser. Details ne porte que des valeurs courtes et
// jamais de secret (mot de passe, jeton, code TOTP).
type Event struct {
	Action      Action
	TargetType  string // "account", "org", "member"…
	TargetID    string
	TargetLabel string // e-mail, slug… : lisible même si la cible disparaît
	Details     map[string]string
}

// Entry est un événement relu.
type Entry struct {
	ID          uuid.UUID
	OccurredAt  time.Time
	ActorUserID int64
	ActorEmail  string
	Event
	IP        string
	RequestID string
}

const (
	maxLabel   = 320
	maxShort   = 64
	maxID      = 128
	maxDetails = 16
	maxValue   = 200
)

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Coupe sur une frontière de caractère.
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// ErrUnknownAction : action absente de Actions.
var ErrUnknownAction = errors.New("audit: action inconnue")

func prepare(a Actor, e Event) (uuid.UUID, []byte, error) {
	if !slices.Contains(Actions(), e.Action) {
		return uuid.UUID{}, nil, fmt.Errorf("%w : %q", ErrUnknownAction, e.Action)
	}
	if len(e.Details) > maxDetails {
		return uuid.UUID{}, nil, fmt.Errorf("audit: %d détails, %d au plus", len(e.Details), maxDetails)
	}
	details := make(map[string]string, len(e.Details))
	for k, v := range e.Details {
		details[clip(k, maxShort)] = clip(v, maxValue)
	}
	body, err := json.Marshal(details)
	if err != nil {
		return uuid.UUID{}, nil, fmt.Errorf("audit: détails : %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.UUID{}, nil, fmt.Errorf("audit: identifiant : %w", err)
	}
	return id, body, nil
}

func actorID(a Actor) any {
	if a.UserID == 0 {
		return nil
	}
	return a.UserID
}

// RecordOrg journalise un événement de l'organisation de tx, dans la transaction de
// l'opération qu'il décrit : pas d'action sans trace, pas de trace sans action.
func RecordOrg(ctx context.Context, tx *db.OrgTx, a Actor, e Event) error {
	id, details, err := prepare(a, e)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_events (org_id, id, actor_user_id, actor_email, action, target_type,
		                          target_id, target_label, details, ip, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		tx.OrgID(), id, actorID(a), clip(a.Email, maxLabel), string(e.Action), clip(e.TargetType, maxShort),
		clip(e.TargetID, maxID), clip(e.TargetLabel, maxLabel), string(details), clip(a.IP, maxShort), clip(a.RequestID, maxShort))
	if err != nil {
		return fmt.Errorf("audit: %s : %w", e.Action, err)
	}
	return nil
}

// RecordInstance journalise un événement sans organisation (table globale), dans la
// transaction q de l'opération qu'il décrit.
func RecordInstance(ctx context.Context, q db.Querier, a Actor, e Event) error {
	id, details, err := prepare(a, e)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO instance_audit_events (id, actor_user_id, actor_email, action, target_type,
		                                   target_id, target_label, details, ip, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, actorID(a), clip(a.Email, maxLabel), string(e.Action), clip(e.TargetType, maxShort),
		clip(e.TargetID, maxID), clip(e.TargetLabel, maxLabel), string(details), clip(a.IP, maxShort), clip(a.RequestID, maxShort))
	if err != nil {
		return fmt.Errorf("audit: %s : %w", e.Action, err)
	}
	return nil
}

// DefaultPage et MaxPage bornent une page du journal.
const (
	DefaultPage = 50
	MaxPage     = 200
)

type cursorKey struct {
	At time.Time `json:"t"`
	ID uuid.UUID `json:"i"`
}

const columns = `id, occurred_at, coalesce(actor_user_id, 0), actor_email, action, target_type,
	target_id, target_label, details, ip, request_id`

// ListOrg relit le journal de l'organisation de tx, du plus récent au plus ancien.
func ListOrg(ctx context.Context, tx *db.OrgTx, cursor string, limit int) (pagination.Page[Entry], error) {
	return list(ctx, tx, "audit_events", cursor, limit)
}

// ListInstance relit le journal de l'instance, du plus récent au plus ancien.
func ListInstance(ctx context.Context, q db.Querier, cursor string, limit int) (pagination.Page[Entry], error) {
	return list(ctx, q, "instance_audit_events", cursor, limit)
}

func list(ctx context.Context, q db.Querier, table, cursor string, limit int) (pagination.Page[Entry], error) {
	if limit < 1 || limit > MaxPage {
		return pagination.Page[Entry]{}, &pagination.LimitError{Max: MaxPage}
	}
	query := `SELECT ` + columns + ` FROM ` + table
	args := []any{limit + 1}
	if cursor != "" {
		var k cursorKey
		if err := pagination.Decode(cursor, &k); err != nil {
			return pagination.Page[Entry]{}, err
		}
		query += ` WHERE (occurred_at, id) < ($2, $3)`
		args = append(args, k.At, k.ID)
	}
	query += ` ORDER BY occurred_at DESC, id DESC LIMIT $1`
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Page[Entry]{}, fmt.Errorf("audit: lecture du journal : %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var action string
		var details []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorUserID, &e.ActorEmail, &action, &e.TargetType,
			&e.TargetID, &e.TargetLabel, &details, &e.IP, &e.RequestID); err != nil {
			return pagination.Page[Entry]{}, fmt.Errorf("audit: lecture du journal : %w", err)
		}
		e.Action = Action(action)
		if err := json.Unmarshal(details, &e.Details); err != nil {
			return pagination.Page[Entry]{}, fmt.Errorf("audit: détails de %s : %w", e.ID, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[Entry]{}, fmt.Errorf("audit: lecture du journal : %w", err)
	}
	return pagination.Build(out, limit, func(e Entry) any { return cursorKey{At: e.OccurredAt, ID: e.ID} })
}
