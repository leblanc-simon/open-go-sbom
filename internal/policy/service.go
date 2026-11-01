package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// Delivery est le mode d'envoi des violations d'une politique.
type Delivery string

// Modes d'envoi.
const (
	DeliveryImmediate Delivery = "immediate"
	DeliveryDigest    Delivery = "digest"
	DeliveryNone      Delivery = "none"
)

// Deliveries renvoie les modes d'envoi, dans l'ordre des écrans.
func Deliveries() []Delivery { return []Delivery{DeliveryImmediate, DeliveryDigest, DeliveryNone} }

// Valid indique un mode connu.
func (d Delivery) Valid() bool { return slices.Contains(Deliveries(), d) }

// Bornes.
const (
	MaxPolicies    = 100
	MaxDescription = 1000
	maxName        = 100
	maxChannels    = 20
)

// Clés de validation.
const (
	KeyNameInvalid        = "validation.policy_name_invalid"
	KeyNameTaken          = "validation.policy_name_taken"
	KeyDescriptionTooLong = "validation.policy_description_too_long"
	KeySubjectInvalid     = "validation.policy_subject_invalid"
	KeyDeliveryInvalid    = "validation.policy_delivery_invalid"
	KeyChannelsInvalid    = "validation.policy_channels_invalid"
	KeyTooMany            = "validation.policies_too_many"
	KeyTemplateInvalid    = "validation.policy_template_invalid"
)

// ErrNotFound : politique, violation ou instantané inconnus.
var ErrNotFound = errors.New("policy: introuvable")

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// Policy est une politique.
type Policy struct {
	ID          uuid.UUID
	Name        string
	Description string
	Subject     Subject
	Expression  string
	Template    string
	Enabled     bool
	Blocking    bool
	Delivery    Delivery
	Channels    []uuid.UUID
	LastError   string
	LastErrorAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// Open est le nombre de violations ouvertes.
	Open int
}

// Input est la saisie d'une politique.
type Input struct {
	Name        string
	Description string
	Subject     Subject
	Expression  string
	Template    string
	Enabled     bool
	Blocking    bool
	Delivery    Delivery
	Channels    []uuid.UUID
}

// Options règle le service.
type Options struct {
	Pool     *db.Pool
	Compiler *Compiler
	// PublicURL est l'URL publique du serveur (liens des verdicts ; vide : sans lien).
	PublicURL string
	Logger    *slog.Logger
	Now       func() time.Time
}

// Service tient les politiques, leur évaluation, les violations et les verdicts.
type Service struct {
	o Options
}

// NewService renvoie le service.
func NewService(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	o.PublicURL = strings.TrimRight(o.PublicURL, "/")
	return &Service{o: o}
}

func (s *Service) now() time.Time { return s.o.Now().UTC().Round(time.Microsecond) }

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok || errors.Is(err, ErrNotFound) {
		return err
	}
	if _, ok := IsExprError(err); ok {
		return err
	}
	return fmt.Errorf("policy: %s : %w", op, err)
}

func uniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// normalize valide une saisie et compile sa règle.
func (s *Service) normalize(in Input) (Input, *Program, error) {
	name := strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > maxName || strings.ContainsFunc(name, unicode.IsControl) {
		return in, nil, invalid("name", KeyNameInvalid)
	}
	in.Name = name
	in.Description = strings.TrimSpace(strings.ReplaceAll(in.Description, "\r\n", "\n"))
	if utf8.RuneCountInString(in.Description) > MaxDescription || !utf8.ValidString(in.Description) {
		return in, nil, invalid("description", KeyDescriptionTooLong)
	}
	if !in.Subject.Valid() {
		return in, nil, invalid("subject", KeySubjectInvalid)
	}
	if !in.Delivery.Valid() {
		return in, nil, invalid("delivery", KeyDeliveryInvalid)
	}
	if in.Template != "" {
		t, ok := TemplateByKey(in.Template)
		if !ok || t.Subject != in.Subject {
			return in, nil, invalid("template", KeyTemplateInvalid)
		}
	}
	in.Expression = strings.TrimSpace(strings.ReplaceAll(in.Expression, "\r\n", "\n"))
	slices.SortFunc(in.Channels, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	in.Channels = slices.Compact(in.Channels)
	if len(in.Channels) > maxChannels {
		return in, nil, invalid("channels", KeyChannelsInvalid)
	}
	prg, err := s.o.Compiler.Compile(in.Subject, in.Expression)
	if err != nil {
		return in, nil, err
	}
	return in, prg, nil
}

const policyColumns = `p.id, p.name, p.description, p.subject, p.expression, coalesce(p.template, ''), p.enabled, p.blocking,
	p.delivery, coalesce(p.last_error, ''), p.last_error_at, p.created_at, p.updated_at,
	coalesce((SELECT array_agg(pc.channel_id ORDER BY pc.channel_id) FROM policy_channels pc
	           WHERE pc.org_id = p.org_id AND pc.policy_id = p.id), '{}'),
	(SELECT count(*) FROM policy_violations v WHERE v.org_id = p.org_id AND v.policy_id = p.id AND v.resolved_at IS NULL)`

func scanPolicy(row interface{ Scan(...any) error }) (Policy, error) {
	var p Policy
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Subject, &p.Expression, &p.Template, &p.Enabled, &p.Blocking,
		&p.Delivery, &p.LastError, &p.LastErrorAt, &p.CreatedAt, &p.UpdatedAt, db.Array(&p.Channels), &p.Open)
	return p, err
}

// List renvoie les politiques de l'organisation, par nom.
func (s *Service) List(ctx context.Context, org tenant.OrgID) ([]Policy, error) {
	var out []Policy
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		out, err = listPolicies(ctx, tx, "")
		return err
	}, db.ReadOnly())
	return out, wrap("liste des politiques", err)
}

func listPolicies(ctx context.Context, tx *db.OrgTx, where string, args ...any) ([]Policy, error) {
	q := `SELECT ` + policyColumns + ` FROM policies p`
	if where != "" {
		q += ` WHERE ` + where
	}
	rows, err := tx.QueryContext(ctx, q+` ORDER BY lower(p.name), p.id LIMIT `+fmt.Sprint(MaxPolicies), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Get renvoie une politique.
func (s *Service) Get(ctx context.Context, org tenant.OrgID, id uuid.UUID) (Policy, error) {
	var p Policy
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		p, err = getPolicy(ctx, tx, id, false)
		return err
	}, db.ReadOnly())
	return p, wrap("lecture d'une politique", err)
}

func getPolicy(ctx context.Context, tx *db.OrgTx, id uuid.UUID, lock bool) (Policy, error) {
	q := `SELECT ` + policyColumns + ` FROM policies p WHERE p.id = $1`
	if lock {
		q += ` FOR UPDATE`
	}
	p, err := scanPolicy(tx.QueryRowContext(ctx, q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	return p, err
}

func policyEvent(action audit.Action, in Input, id uuid.UUID) audit.Event {
	return audit.Event{Action: action, TargetType: "policy", TargetID: id.String(), TargetLabel: in.Name,
		Details: map[string]string{"subject": string(in.Subject), "enabled": fmt.Sprint(in.Enabled),
			"blocking": fmt.Sprint(in.Blocking), "delivery": string(in.Delivery), "expression": in.Expression}}
}

// setChannels remplace les canaux d'une politique ; un canal inconnu est refusé.
func setChannels(ctx context.Context, tx *db.OrgTx, id uuid.UUID, channels []uuid.UUID) error {
	if len(channels) > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_channels WHERE id = ANY($1::uuid[])`,
			channels).Scan(&n); err != nil {
			return err
		}
		if n != len(channels) {
			return invalid("channels", KeyChannelsInvalid)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_channels WHERE policy_id = $1`, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO policy_channels (org_id, policy_id, channel_id)
		SELECT $1, $2, c FROM unnest($3::uuid[]) AS c`, tx.OrgID(), id, channels)
	return err
}

// Create enregistre une politique et met en file l'évaluation de l'organisation.
func (s *Service) Create(ctx context.Context, org tenant.OrgID, actor audit.Actor, in Input) (Policy, error) {
	in, _, err := s.normalize(in)
	if err != nil {
		return Policy{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM policies`).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPolicies {
			return invalid("name", KeyTooMany)
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `INSERT INTO policies (org_id, id, name, description, subject, expression, template,
			enabled, blocking, delivery, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, $10, $11, $11)`,
			tx.OrgID(), id, in.Name, in.Description, in.Subject, in.Expression, in.Template, in.Enabled, in.Blocking,
			in.Delivery, now); err != nil {
			if uniqueViolation(err) {
				return invalid("name", KeyNameTaken)
			}
			return err
		}
		if err := setChannels(ctx, tx, id, in.Channels); err != nil {
			return err
		}
		if err := audit.RecordOrg(ctx, tx, actor, policyEvent(audit.PolicyCreated, in, id)); err != nil {
			return err
		}
		if in.Enabled {
			if err := EnqueueOrg(ctx, tx); err != nil {
				return err
			}
		}
		p, err = getPolicy(ctx, tx, id, false)
		return err
	})
	return p, wrap("création d'une politique", err)
}

// Update modifie une politique. Une règle désactivée ou dont l'expression ou le sujet
// change voit ses violations ouvertes résolues ; une règle active est réévaluée.
func (s *Service) Update(ctx context.Context, org tenant.OrgID, actor audit.Actor, id uuid.UUID, in Input) (Policy, error) {
	in, _, err := s.normalize(in)
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		old, err := getPolicy(ctx, tx, id, true)
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `UPDATE policies SET name = $2, description = $3, subject = $4, expression = $5,
			enabled = $6, blocking = $7, delivery = $8, updated_at = $9,
			last_error = CASE WHEN expression = $5 THEN last_error END,
			last_error_at = CASE WHEN expression = $5 THEN last_error_at END WHERE id = $1`,
			id, in.Name, in.Description, in.Subject, in.Expression, in.Enabled, in.Blocking, in.Delivery, now); err != nil {
			if uniqueViolation(err) {
				return invalid("name", KeyNameTaken)
			}
			return err
		}
		if !in.Enabled || old.Subject != in.Subject || old.Expression != in.Expression {
			if _, err := tx.ExecContext(ctx, `UPDATE policy_violations SET resolved_at = greatest($2, opened_at)
				WHERE policy_id = $1 AND resolved_at IS NULL`, id, now); err != nil {
				return err
			}
		}
		if err := setChannels(ctx, tx, id, in.Channels); err != nil {
			return err
		}
		if err := audit.RecordOrg(ctx, tx, actor, policyEvent(audit.PolicyUpdated, in, id)); err != nil {
			return err
		}
		if in.Enabled {
			if err := EnqueueOrg(ctx, tx); err != nil {
				return err
			}
		}
		p, err = getPolicy(ctx, tx, id, false)
		return err
	})
	return p, wrap("modification d'une politique", err)
}

// Delete supprime une politique, ses violations et leurs envois.
func (s *Service) Delete(ctx context.Context, org tenant.OrgID, actor audit.Actor, id uuid.UUID) error {
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err := getPolicy(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, policyEvent(audit.PolicyDeleted, Input{Name: p.Name, Subject: p.Subject,
			Enabled: p.Enabled, Blocking: p.Blocking, Delivery: p.Delivery, Expression: p.Expression}, id))
	})
	return wrap("suppression d'une politique", err)
}

// Check compile une règle sans l'enregistrer (validation de l'écran).
func (s *Service) Check(subject Subject, expr string) error {
	if !subject.Valid() {
		return invalid("subject", KeySubjectInvalid)
	}
	_, err := s.o.Compiler.Compile(subject, strings.TrimSpace(expr))
	return err
}
