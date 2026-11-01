package triage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/version"
)

// Bornes des saisies.
const (
	MaxComment = 4000
	// MaxAcceptance borne l'échéance d'un risque accepté.
	MaxAcceptance = 3 * 365 * 24 * time.Hour
)

// Clés de validation (validation.*).
const (
	KeyStatusInvalid        = "validation.triage_status_invalid"
	KeyJustificationNeeded  = "validation.triage_justification_required"
	KeyJustificationInvalid = "validation.triage_justification_invalid"
	KeyJustificationUnused  = "validation.triage_justification_unused"
	KeyCommentRequired      = "validation.triage_comment_required"
	KeyCommentTooLong       = "validation.triage_comment_too_long"
	KeyExpiryRequired       = "validation.triage_expiry_required"
	KeyExpiryInvalid        = "validation.triage_expiry_invalid"
	KeyExpiryUnused         = "validation.triage_expiry_unused"
	KeyScopeInvalid         = "validation.triage_scope_invalid"
	KeyVersInvalid          = "validation.triage_vers_invalid"
	KeyVersUnused           = "validation.triage_vers_unused"
)

// ErrNotFound : constat ou décision inconnus dans l'organisation (ou le projet).
var ErrNotFound = errors.New("triage: introuvable")

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// ExpireKind est le job qui fait échoir un risque accepté (charge {"decision_id"}).
const ExpireKind = "triage.expire"

// ExpirePayload est la charge d'ExpireKind.
type ExpirePayload struct {
	DecisionID uuid.UUID `json:"decision_id"`
}

// SystemLabel est l'auteur des échéances.
const SystemLabel = "system"

// Options règle le service.
type Options struct {
	Pool     *db.Pool
	Comparer version.Comparer
	Now      func() time.Time
	Logger   *slog.Logger
	// OnChange, facultatif, reçoit les constats dont le statut effectif change, dans la
	// transaction qui les change (alertes de T15 : mise en file dans la transaction).
	OnChange func(ctx context.Context, tx *db.OrgTx, changes []Change) error
}

// Service tient les décisions de triage et le statut effectif des constats.
type Service struct {
	o        Options
	resolver Resolver
}

// NewService renvoie le service.
func NewService(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{o: o, resolver: NewResolver(o.Comparer)}
}

// Resolver renvoie le calcul des statuts effectifs du service.
func (s *Service) Resolver() Resolver { return s.resolver }

func (s *Service) now() time.Time { return s.o.Now().UTC().Round(time.Microsecond) }

// Input est une décision prise dans l'interface sur un constat.
type Input struct {
	ProjectID     uuid.UUID
	FindingID     uuid.UUID
	Scope         Scope
	Status        Status
	Justification Justification
	Comment       string
	ExpiresOn     *time.Time // date UTC
	// Vers restreint une décision d'organisation à une plage de versions (vide : toutes).
	Vers string
}

// cleanComment normalise un commentaire : espaces de bord retirés, fins de ligne
// unifiées, caractères de contrôle refusés.
func cleanComment(s string) (string, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) {
		return "", false
	}
	return s, utf8.RuneCountInString(s) <= MaxComment
}

// validate vérifie une décision (hors retrait) ; requireComment pour l'interface.
func (s *Service) validate(d *Decision, requireComment bool, purlType string) error {
	if _, err := ParseStatus(string(d.Status)); err != nil {
		return invalid("status", KeyStatusInvalid)
	}
	comment, ok := cleanComment(d.Comment)
	if !ok {
		return invalid("comment", KeyCommentTooLong)
	}
	d.Comment = comment
	if requireComment && comment == "" {
		return invalid("comment", KeyCommentRequired)
	}
	switch {
	case d.Status == StatusNotAffected && d.Justification == "" && comment == "":
		return invalid("justification", KeyJustificationNeeded)
	case d.Status == StatusNotAffected && d.Justification != "":
		if _, err := ParseJustification(string(d.Justification)); err != nil {
			return invalid("justification", KeyJustificationInvalid)
		}
	case d.Status != StatusNotAffected && d.Justification != "":
		return invalid("justification", KeyJustificationUnused)
	}
	if d.Status == StatusRiskAccepted {
		if d.ExpiresOn == nil {
			return invalid("expires_on", KeyExpiryRequired)
		}
		today := s.now().Truncate(24 * time.Hour)
		if d.ExpiresOn.Before(today) || d.ExpiresOn.After(today.Add(MaxAcceptance)) {
			return invalid("expires_on", KeyExpiryInvalid)
		}
	} else if d.ExpiresOn != nil {
		return invalid("expires_on", KeyExpiryUnused)
	}
	if d.Vers != "" {
		if d.Scope != ScopeOrg {
			return invalid("vers", KeyVersUnused)
		}
		r, err := version.ParseVers(d.Vers, s.o.Comparer)
		if err != nil || r.Scheme != version.ForPURLType(purlType) {
			return invalid("vers", KeyVersInvalid)
		}
		d.Vers = r.String()
	}
	return nil
}

// target lit le constat d'un projet.
func target(ctx context.Context, tx *db.OrgTx, projectID, findingID uuid.UUID) (findingTarget, error) {
	ts, err := queryTargets(ctx, tx, `f.id = $1 AND f.project_id = $2`, findingID, projectID)
	if err != nil {
		return findingTarget{}, err
	}
	if len(ts) == 0 {
		return findingTarget{}, ErrNotFound
	}
	return ts[0], nil
}

// Decide enregistre une décision (ou un retrait) sur un constat, recalcule le statut
// effectif des constats concernés et journalise : dans une seule transaction, sous le
// verrou exclusif du triage de l'organisation. Le droit de l'acteur (finding.triage sur
// le projet, triage.org pour toute l'organisation) est vérifié par l'appelant.
func (s *Service) Decide(ctx context.Context, org tenant.OrgID, actor audit.Actor, in Input) (d Decision, changes []Change, err error) {
	if in.Scope != ScopeProject && in.Scope != ScopeOrg {
		return Decision{}, nil, invalid("scope", KeyScopeInvalid)
	}
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		t, err := target(ctx, tx, in.ProjectID, in.FindingID)
		if err != nil {
			return err
		}
		d = Decision{Scope: in.Scope, VulnID: t.Target.VulnID, PURLBase: t.Target.PURLBase, Action: ActionSet,
			Status: in.Status, Justification: in.Justification, Comment: in.Comment, ExpiresOn: in.ExpiresOn, Vers: in.Vers,
			AuthorUserID: actor.UserID, AuthorLabel: authorLabel(actor)}
		if in.Scope == ScopeProject {
			d.ProjectID, d.PURL = t.ProjectID, t.Target.PURL
		}
		if err := s.validate(&d, true, t.Target.PURLType); err != nil {
			return err
		}
		if err := lock(ctx, tx, true); err != nil {
			return err
		}
		if d.ID, err = uuid.NewV7(); err != nil {
			return err
		}
		d.CreatedAt = s.now()
		if err := insertDecisions(ctx, tx, []Decision{d}); err != nil {
			return err
		}
		if err := s.scheduleExpiry(ctx, tx, d); err != nil {
			return err
		}
		if changes, err = s.recompute(ctx, tx, []pair{{d.PURLBase, d.VulnID}}); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, auditEvent(audit.TriageDecided, d, t.ID, len(changes)))
	})
	if err != nil {
		return Decision{}, nil, wrapNotFound(err)
	}
	return d, changes, nil
}

// Withdraw retire une décision courante : sa clé n'a plus de décision, et les constats
// retombent sur la décision de l'organisation, ou « à analyser ». projectID non nul
// exige une décision de ce projet ; nul, une décision d'organisation. ErrNotFound si la
// décision n'est pas (ou plus) la décision courante de sa clé. Le droit de l'acteur est
// vérifié par l'appelant.
func (s *Service) Withdraw(ctx context.Context, org tenant.OrgID, actor audit.Actor, decisionID, projectID uuid.UUID) (w Decision, changes []Change, err error) {
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if err := lock(ctx, tx, true); err != nil {
			return err
		}
		d, err := s.currentDecision(ctx, tx, decisionID, projectID)
		if err != nil {
			return err
		}
		w = Decision{Scope: d.Scope, ProjectID: d.ProjectID, VulnID: d.VulnID, PURL: d.PURL, PURLBase: d.PURLBase,
			Vers: d.Vers, Action: ActionWithdraw, AuthorUserID: actor.UserID, AuthorLabel: authorLabel(actor), CreatedAt: s.now()}
		if w.ID, err = uuid.NewV7(); err != nil {
			return err
		}
		if err := insertDecisions(ctx, tx, []Decision{w}); err != nil {
			return err
		}
		if changes, err = s.recompute(ctx, tx, []pair{{d.PURLBase, d.VulnID}}); err != nil {
			return err
		}
		e := auditEvent(audit.TriageWithdrawn, w, uuid.Nil, len(changes))
		e.Details["withdrawn"] = d.ID.String()
		return audit.RecordOrg(ctx, tx, actor, e)
	})
	if err != nil {
		return Decision{}, nil, wrapNotFound(err)
	}
	return w, changes, nil
}

// currentDecision lit une décision qui doit être la décision courante de sa clé, du
// projet projectID (ou d'organisation si nul).
func (s *Service) currentDecision(ctx context.Context, tx *db.OrgTx, decisionID, projectID uuid.UUID) (Decision, error) {
	d, err := getDecision(ctx, tx, decisionID)
	if errNoRows(err) {
		return Decision{}, ErrNotFound
	}
	if err != nil {
		return Decision{}, err
	}
	if d.Action == ActionWithdraw || d.ProjectID != projectID || (projectID == uuid.Nil) != (d.Scope == ScopeOrg) {
		return Decision{}, ErrNotFound
	}
	logs, err := decisionsFor(ctx, tx, []pair{{d.PURLBase, d.VulnID}})
	if err != nil {
		return Decision{}, err
	}
	if !isCurrent(logs[pair{d.PURLBase, d.VulnID}], d) {
		return Decision{}, ErrNotFound
	}
	return d, nil
}

// Current renvoie une décision courante du projet projectID (ou d'organisation si nul),
// pour la page de confirmation d'un retrait. ErrNotFound sinon.
func (s *Service) Current(ctx context.Context, org tenant.OrgID, decisionID, projectID uuid.UUID) (d Decision, err error) {
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		d, err = s.currentDecision(ctx, tx, decisionID, projectID)
		return err
	}, db.ReadOnly())
	return d, wrapNotFound(err)
}

func authorLabel(a audit.Actor) string {
	if a.Email != "" {
		return a.Email
	}
	return SystemLabel
}

func auditEvent(action audit.Action, d Decision, findingID uuid.UUID, changed int) audit.Event {
	details := map[string]string{"scope": string(d.Scope), "vuln": d.VulnID, "decision": d.ID.String(),
		"changed": fmt.Sprint(changed)}
	if d.Status != "" {
		details["status"] = string(d.Status)
	}
	if d.Justification != "" {
		details["justification"] = string(d.Justification)
	}
	if d.ExpiresOn != nil {
		details["expires_on"] = d.ExpiresOn.Format(time.DateOnly)
	}
	if d.Vers != "" {
		details["vers"] = d.Vers
	}
	label := d.VulnID + " · " + d.PURLBase
	if d.PURL != "" {
		label = d.VulnID + " · " + d.PURL
	}
	e := audit.Event{Action: action, TargetType: "finding", TargetLabel: label, Details: details}
	if findingID != uuid.Nil {
		e.TargetID = findingID.String()
	}
	return e
}

// scheduleExpiry met en file l'échéance d'un risque accepté, dans la transaction de la
// décision.
func (s *Service) scheduleExpiry(ctx context.Context, tx *db.OrgTx, d Decision) error {
	if d.Action != ActionSet || d.Status != StatusRiskAccepted {
		return nil
	}
	_, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: ExpireKind, Payload: ExpirePayload{DecisionID: d.ID},
		UniqueKey: "decision:" + d.ID.String(), RunAt: d.ExpiresAt()})
	return err
}

// ExpireHandler est le handler d'ExpireKind.
func (s *Service) ExpireHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		var p ExpirePayload
		if err := e.Decode(&p); err != nil {
			return err
		}
		if e.OrgID.IsZero() || p.DecisionID == uuid.Nil {
			return jobs.Permanent(errors.New("triage: échéance sans organisation ni décision"))
		}
		_, err := s.Expire(ctx, e.OrgID, p.DecisionID)
		return err
	})
}

// Expire fait échoir un risque accepté : si la décision est toujours la décision courante
// de sa clé et que son échéance est passée, une ligne « échéance » (statut « à analyser »,
// auteur système) prend sa suite et le statut effectif est recalculé. Idempotent : une
// décision déjà remplacée ou échue ne change rien ; une échéance pas encore atteinte
// (horloges décalées) est remise en file à sa date. Renvoie vrai si la décision a échu.
func (s *Service) Expire(ctx context.Context, org tenant.OrgID, decisionID uuid.UUID) (bool, error) {
	expired := false
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if err := lock(ctx, tx, true); err != nil {
			return err
		}
		d, err := getDecision(ctx, tx, decisionID)
		if errNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Action != ActionSet || d.Status != StatusRiskAccepted {
			return nil
		}
		logs, err := decisionsFor(ctx, tx, []pair{{d.PURLBase, d.VulnID}})
		if err != nil {
			return err
		}
		if !isCurrent(logs[pair{d.PURLBase, d.VulnID}], d) {
			return nil
		}
		now := s.now()
		if now.Before(d.ExpiresAt()) {
			return s.scheduleExpiry(ctx, tx, d)
		}
		x := Decision{Scope: d.Scope, ProjectID: d.ProjectID, VulnID: d.VulnID, PURL: d.PURL, PURLBase: d.PURLBase,
			Vers: d.Vers, Action: ActionExpire, Status: StatusInTriage, AuthorLabel: SystemLabel, ExpiresID: d.ID, CreatedAt: now}
		if x.ID, err = uuid.NewV7(); err != nil {
			return err
		}
		if err := insertDecisions(ctx, tx, []Decision{x}); err != nil {
			return err
		}
		changes, err := s.recompute(ctx, tx, []pair{{d.PURLBase, d.VulnID}})
		if err != nil {
			return err
		}
		expired = true
		e := auditEvent(audit.TriageExpired, x, uuid.Nil, len(changes))
		e.Details["expired"] = d.ID.String()
		e.Details["expires_on"] = d.ExpiresOn.Format(time.DateOnly)
		return audit.RecordOrg(ctx, tx, audit.System, e)
	})
	return expired, wrap("échéance d'un risque accepté", err)
}

func isCurrent(log []Decision, d Decision) bool {
	for _, c := range Current(log) {
		if c.key() == d.key() {
			return c.ID == d.ID
		}
	}
	return false
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("triage: %s : %w", what, err)
}

// wrapNotFound laisse passer les erreurs connues (introuvable, validation) telles quelles.
func wrapNotFound(err error) error {
	var ve *account.ValidationError
	if errors.Is(err, ErrNotFound) || errors.As(err, &ve) {
		return err
	}
	return wrap("décision", err)
}
